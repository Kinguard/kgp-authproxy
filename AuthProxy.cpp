#include "AuthProxy.h"

#include <libutils/Socket.h>
#include <libutils/String.h>
#include <libutils/Logger.h>

#include <json/json.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <crypt.h>
#include <fcntl.h>

#include <iostream>
#include <vector>

using namespace std;
using namespace Utils;
using namespace Utils::Net;

AuthProxy::AuthProxy(const string &socketpath):
	Utils::Net::NetServer(UnixStreamServerSocketPtr( new UnixStreamServerSocket(socketpath)), 0)
{
}

void AuthProxy::HandleHello(UnixStreamClientSocketPtr sock, const string &line)
{
	logg << Logger::Debug << "Got hello from server " << lend;

}


/*
 * Return sha512-crypted passwd
 */

const static string valid =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	"./";

string AuthProxy::HashPassword(const string &pwd)
{
	int fd = open("/dev/urandom",O_RDONLY);

	if ( fd < 0 )
	{
		logg << Logger::Error << "Failed to open random device"<< lend;
		return "";
	}

	char buf[16];
	ssize_t rd,total=0;
	while( (rd = read(fd, buf+total, 16 - total) ) > 0 )
	{
		total += rd;
	}
	close(fd);

	if( total != 16 )
	{
		logg << Logger::Error << "Failed to read random data"<< lend;
		return "";
	}

	stringstream ret;
	ret << "$6$";
	for( int i=0; i<16; i++)
	{
		ret << valid[  buf[i] % valid.size() ];
	}

	struct crypt_data data;

	data.initialized = 0;

	return crypt_r( pwd.c_str() ,ret.str().c_str(), &data);
}

void AuthProxy::SendReply(UnixStreamClientSocketPtr sock, const Json::Value &val)
{
	string res = "O"+writer.write(val)+"\n";
	sock->Write( res.c_str(), res.size() );
}

void AuthProxy::SendError(UnixStreamClientSocketPtr sock)
{
	sock->Write("F\n", 2);
}

void AuthProxy::HandlePassdb(UnixStreamClientSocketPtr sock, const string &line)
{
	logg << Logger::Debug << "Passdb lookup " << line << lend;

	UnixStreamClientSocket secop("/tmp/secop");
	Json::Value req;

	req["tid"]=0;
	req["version"]=1.0;
	req["cmd"]="getidentifiers";
	req["username"] = line;
	req["servicename"] = "opiuser";

	string r = this->writer.write( req );

	secop.Write(r.c_str(), r.size() );

	char buf[16384];
	int rd;

	Json::Value reply;
	reply["password"] = "test";
	reply["userdb_home"] = "/var/opi/mail/data/"+line+"/home";
	reply["userdb_uid"]  = 5000;
	reply["userdb_gid"]  = 5000;

	if( ( rd = secop.Read( buf, sizeof(buf) ) ) > 0  )
	{
		Json::Value resp;
		Json::Reader reader;

		if( ! reader.parse( buf, buf+rd, resp ) )
		{
			logg << Logger::Error << "Failed to parse response"<<lend;
			this->SendError(sock);
			return;
		}

		if( ! resp.isMember("status") || ! resp["status"].isMember("value") )
		{
			logg << Logger::Debug << "Request failed, missing arguments " <<lend;
			this->SendError(sock);
			return;
		}

		if( resp["status"]["value"] == 0 )
		{
			reply["password"]= this->HashPassword( resp["identifiers"][(Json::Value::UInt)0]["password"].asString() );
		}
		else
		{
			logg << Logger::Debug << "Request failed "<< resp["status"]["desc"].asString() <<lend;
			this->SendError(sock);
			return;
		}

	}

	this->SendReply(sock, reply);
}

void AuthProxy::HandleUserdb(UnixStreamClientSocketPtr sock, const string &line)
{
	logg << Logger::Debug << "Userdb lookup " << line << lend;

	Json::Value reply;

	reply["home"]	= "/var/opi/mail/data/"+line+"/home";
	reply["uid"]	= 5000;
	reply["gid"]	= 5000;

	this->SendReply(sock, reply);
}

void AuthProxy::HandleLookup(UnixStreamClientSocketPtr sock, const string &line)
{
	logg << Logger::Debug << "Got lookup from server " << lend;

	vector<string> words;
	String::Split(line, words, "/",3);

	// index 0 - Namespace 1 - type 2 - argument
	if( words.size() == 3 )
	{
		if( words[0] == "shared" )
		{
			if( words[1] == "passdb")
			{
				this->HandlePassdb(sock, words[2]);
				return;
			}
			else if ( words[1] == "userdb" )
			{
				this->HandleUserdb(sock, words[2]);
				return;
			}
			else
			{
				logg << Logger::Error << "Unknown type "<< words[1]<<lend;
			}
		}
		else
		{
			logg << Logger::Error << "Unknown namespace "<< words[0]<<lend;
		}
	}
	else
	{
		logg << Logger::Error << "Wrong number of arguments for lookup" << lend;
	}

	this->SendError(sock);
}

void AuthProxy::Dispatch(SocketPtr con)
{
	// Convert into unixsocket
	UnixStreamClientSocketPtr sock = static_pointer_cast<UnixStreamClientSocket>(con);

	char buf[1024];
	size_t rd;

	if( (rd = sock->Read( buf, sizeof(buf) ) ) > 0  )
	{
		vector<string> lines;

		String::Split(buf, lines, "\n");
		for(auto& line: lines)
		{
			//cout << "Line ["<<line <<"]"<<endl;
			if( line.size() > 0 )
			{
				switch(line[0])
				{
				case 'H':
					this->HandleHello(sock, line.substr(1) );
					break;
				case 'L':
					this->HandleLookup(sock, line.substr(1));
					break;
				default:
					logg << Logger::Info << "Unknown command"<<line[0]<<lend;
					break;
				}
			}
		}

	}

	this->decreq();
}

AuthProxy::~AuthProxy()
{
}
