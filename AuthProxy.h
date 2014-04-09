#ifndef AUTHPROXY_H
#define AUTHPROXY_H

#include <string>
#include <memory>

#include <libutils/NetServer.h>
#include <json/json.h>

using namespace std;
using namespace Utils::Net;

class AuthProxy : public Utils::Net::NetServer
{
public:
	AuthProxy(const string& socketpath);

	virtual void Dispatch(SocketPtr con);

	virtual ~AuthProxy();
private:
	void HandleHello(UnixStreamClientSocketPtr sock, const string& line);

	void SendReply(UnixStreamClientSocketPtr sock, const Json::Value& val);

	void HandlePassdb(UnixStreamClientSocketPtr sock, const string& line);
	void HandleUserdb(UnixStreamClientSocketPtr sock, const string& line);
	void HandleLookup(UnixStreamClientSocketPtr sock, const string& line);

	Json::FastWriter writer;

};

typedef std::shared_ptr<AuthProxy> AuthProxyPtr;

#endif // AUTHPROXY_H
