#include "AuthProxy.h"

#include <libutils/Socket.h>
#include <libutils/String.h>
#include <libutils/Logger.h>

#include <libopi/Secop.h>

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
	(void) sock;
	(void) line;
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
	string res = "O"+writer.write(val);
	try
	{
		sock->Write( res.c_str(), res.size() );
	}
	catch(ErrnoException &e)
	{
		logg << Logger::Info << "Failed to send reply: " << e.what() << lend;
	}
}

void AuthProxy::SendError(UnixStreamClientSocketPtr sock)
{
	try
	{
		sock->Write("F\n", 2);
	}
	catch(ErrnoException &e)
	{
		logg << Logger::Info << "Failed to send error reply: " << e.what() << lend;
	}
}

void AuthProxy::HandlePassdb(UnixStreamClientSocketPtr sock, const string &line)
{
	list<map<string,string>> ids;
	// User might not exist in secop and then an exception will get thrown
	try
	{
		OPI::Secop sec;

		sec.SockAuth();

		ids = sec.GetIdentifiers( line, "opiuser");
	}
	catch(std::runtime_error& e)
	{
		logg << Logger::Error << "Retrieve identifiers for user " << line << " failed ("<<e.what()<<")"<<lend;
		this->SendError(sock);
		return;
	}

	if( ids.size() == 0 )
	{
		logg << Logger::Error << "Unable to get identifiers from backend"<<lend;
		this->SendError(sock);
		return;
	}

	if( ids.front().find("password") == ids.front().end() )
	{
		logg << Logger::Error << "Malformed response from backend"<<lend;
		this->SendError(sock);
		return;
	}

	Json::Value reply;
	reply["password"] = this->HashPassword( ids.front()["password"] );
	reply["userdb_home"] = "/var/opi/mail/data/"+line+"/home";
	reply["userdb_uid"]  = 5000;
	reply["userdb_gid"]  = 5000;

	if( reply["password"].asString() == "" )
	{
		logg << Logger::Error << "Unable to hash password"<<lend;
		this->SendError(sock);
		return;
	}

	this->SendReply(sock, reply);
}

/*
 *TODO: Check with Secop if user exists
 */
void AuthProxy::HandleUserdb(UnixStreamClientSocketPtr sock, const string &line)
{
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

	do
	{
		try
		{
			rd = sock->Read( buf, sizeof(buf) - 1 );
		}
		catch(ErrnoException &e)
		{
			logg << Logger::Error << "Failed to read request from client: "<<e.what()<<lend;
			this->decreq();
			return;
		}

		if( rd <= 0 )
		{
			break;
		}

		vector<string> lines;

		buf[rd] = 0;

		String::Split(buf, lines, "\n");
		for(auto& line: lines)
		{
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

	}while( rd > 0 );

	this->decreq();
}

AuthProxy::~AuthProxy()
{
}
