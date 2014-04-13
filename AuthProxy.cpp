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


/* Wrapper to communicate with Secop
 *
 *NOTE: Not yet fully tested and no unittests written!
 *
 *Use with caution!
 *
 */
class SecopHelper
{
public:
	SecopHelper(): tid(0), secop("/tmp/secop")
	{

	}

	bool Init(const string& pwd)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]= "init";
		cmd["pwd"]=pwd;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	int Status()
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]="status";

		Json::Value rep = this->DoCall(cmd);

		if( this->CheckReply(rep) )
		{
			return rep["server"]["state"].asInt();
		}
		return 0;
	}

	bool SockAuth()
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]= "auth";
		cmd["type"]="socket";

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	bool PlainAuth(const string& user, const string& pwd)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]		= "auth";
		cmd["type"]		= "plain";
		cmd["username"]	= user;
		cmd["password"]	= pwd;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	bool CreateUser(const string& user, const string& pwd)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]		= "createuser";
		cmd["username"]	= user;
		cmd["password"]	= pwd;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	bool RemoveUser(const string& user)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]		= "removeuser";
		cmd["username"]	= user;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}


	vector<string> GetUsers()
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]= "getusers";

		Json::Value rep = this->DoCall(cmd);

		vector<string> users;
		if( this->CheckReply(rep) )
		{
			for(auto x: rep["users"])
			{
				users.push_back(x.asString() );
			}
		}
		return users;
	}

	vector<string> GetServices(const string& user)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]		= "getservices";
		cmd["username"]	= user;

		Json::Value rep = this->DoCall(cmd);

		vector<string> services;
		if( this->CheckReply(rep) )
		{
			for(auto x: rep["services"])
			{
				services.push_back(x.asString() );
			}
		}
		return services;
	}

	bool AddService(const string& user, const string& service)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "addservice";
		cmd["username"]		= user;
		cmd["servicename"]	= service;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	bool RemoveService(const string& user, const string& service)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "removeservice";
		cmd["username"]		= user;
		cmd["servicename"]	= service;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	vector<string> GetACL(const string& user, const string& service)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]		= "getacl";
		cmd["username"]	= user;
		cmd["servicename"]	= service;

		Json::Value rep = this->DoCall(cmd);

		vector<string> acl;
		if( this->CheckReply(rep) )
		{
			for(auto x: rep["acl"])
			{
				acl.push_back(x.asString() );
			}
		}
		return acl;
	}

	bool AddACL(const string& user, const string& service, const string& acl)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "addacl";
		cmd["username"]		= user;
		cmd["servicename"]	= service;
		cmd["acl"]			= acl;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	bool RemoveACL(const string& user, const string& service, const string& acl)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "removeacl";
		cmd["username"]		= user;
		cmd["servicename"]	= service;
		cmd["acl"]			= acl;

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	bool HasACL(const string& user, const string& service, const string& acl)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "hasacl";
		cmd["username"]		= user;
		cmd["servicename"]	= service;
		cmd["acl"]			= acl;

		Json::Value rep = this->DoCall(cmd);
		bool ret = false;

		if ( this->CheckReply(rep) )
		{
			ret = rep["hasacl"].asBool();
		}

		return ret;
	}

	/* Limited, can only add key value string pairs */
	bool AddIdentifier(const string& user, const string& service, const map<string,string>& identifier)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "addidentifier";
		cmd["username"]		= user;
		cmd["servicename"]	= service;

		for(const auto& x: identifier)
		{
			cmd["identifier"][ x.first ] = x.second;
		}

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	/* Identifier has to contain user &| service */
	bool RemoveIdentifier(const string& user, const string& service, const map<string,string>& identifier)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "removeidentifier";
		cmd["username"]		= user;
		cmd["servicename"]	= service;

		for(const auto& x: identifier)
		{
			cmd["identifier"][ x.first ] = x.second;
		}

		Json::Value rep = this->DoCall(cmd);

		return this->CheckReply(rep);
	}

	list<map<string,string>> GetIdentifiers(const string& user, const string& service)
	{
		Json::Value cmd(Json::objectValue);

		cmd["cmd"]			= "getidentifiers";
		cmd["username"]		= user;
		cmd["servicename"]	= service;

		Json::Value rep = this->DoCall(cmd);

		list<map<string,string> > ret;
		//logg << Logger::Debug << rep.toStyledString()<< lend;
		if ( this->CheckReply(rep) )
		{
			for( auto x: rep["identifiers"] )
			{
				Json::Value::Members mems = x.getMemberNames();
				map<string,string> id;
				for( auto mem: mems)
				{
					id[ mem ] = x[mem].asString();
				}
				ret.push_back( id );
			}
		}

		return ret;
	}

	virtual ~SecopHelper()
	{

	}
protected:
	Json::Value DoCall(Json::Value& cmd)
	{
		cmd["tid"]=this->tid;
		cmd["version"]=1.0;
		string r = this->writer.write( cmd );

		this->secop.Write(r.c_str(), r.size() );

		char buf[16384];
		int rd;

		Json::Value resp;

		if( ( rd = this->secop.Read( buf, sizeof(buf) ) ) > 0  )
		{

			if( ! this->reader.parse( buf, buf+rd, resp ) )
			{
				logg << Logger::Error << "Failed to parse response"<<lend;
			}

		}

		return resp;
	}

	bool CheckReply( const Json::Value& val )
	{
		bool ret = false;

		if( val.isMember("status") && val["status"].isObject() )
		{
			ret = val["status"]["value"].asInt() == 0;
		}

		return ret;
	}


	int tid;
private:
	UnixStreamClientSocket secop;
	Json::FastWriter writer;
	Json::Reader reader;
};


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

	SecopHelper sec;

	sec.SockAuth();

	list<map<string,string>> ids = sec.GetIdentifiers( line, "opiuser");

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
