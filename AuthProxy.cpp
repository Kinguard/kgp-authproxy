#include "AuthProxy.h"

#include <libutils/Socket.h>
#include <libutils/String.h>
#include <libutils/Logger.h>

#include <json/json.h>

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

void AuthProxy::SendReply(UnixStreamClientSocketPtr sock, const Json::Value &val)
{
	string res = "O"+writer.write(val)+"\n";
	sock->Write( res.c_str(), res.size() );
}

void AuthProxy::HandlePassdb(UnixStreamClientSocketPtr sock, const string &line)
{
	Json::Value reply;

	reply["password"] = "test";
	reply["userdb_home"] = "/home/username/";
	reply["userdb_uid"]  = 1000;
	reply["userdb_gid"]  = 1000;

	this->SendReply(sock, reply);
}

void AuthProxy::HandleUserdb(UnixStreamClientSocketPtr sock, const string &line)
{
	Json::Value reply;

	reply["home"]	= "/home/username/";
	reply["uid"]	= 1000;
	reply["gid"]	= 1000;

	this->SendReply(sock, reply);
}

void AuthProxy::HandleLookup(UnixStreamClientSocketPtr sock, const string &line)
{
	logg << Logger::Debug << "Got lookup from server " << lend;

	vector<string> words;
	String::Split(line, words, "/",3);

	string ret = "F\n";

	// index 0 - Namespace 1 - type 2 - argument
	if( words.size() == 3 )
	{
		if( words[0] == "shared" )
		{
			if( words[1] == "passdb")
			{
				this->HandlePassdb(sock, words[2]);
			}
			else if ( words[1] == "userdb" )
			{
				this->HandleUserdb(sock, words[2]);
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

	sock->Write(ret.c_str(), ret.size() );
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
			cout << "Line ["<<line <<"]"<<endl;
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
