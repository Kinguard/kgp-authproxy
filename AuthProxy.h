#ifndef AUTHPROXY_H
#define AUTHPROXY_H

#include <string>
#include <memory>

#include <libutils/NetServer.h>
#include <nlohmann/json.hpp>

using namespace std;
using namespace Utils::Net;

using json = nlohmann::json;

class AuthProxy : public Utils::Net::NetServer
{
public:
	AuthProxy(const string& socketpath);

	void Dispatch(SocketPtr con) override;

private:
	void HandleHello(const UnixStreamClientSocketPtr& sock, const string& line);

	void SendReply(const UnixStreamClientSocketPtr& sock, const json& val);
	void SendError(const UnixStreamClientSocketPtr& sock);

	void HandlePassdb(const UnixStreamClientSocketPtr& sock, const string& line);
	void HandleUserdb(const UnixStreamClientSocketPtr& sock, const string& line);
	void HandleLookup(const UnixStreamClientSocketPtr& sock, const string& line);

	string HashPassword(const string& pwd);
};

typedef std::shared_ptr<AuthProxy> AuthProxyPtr;

#endif // AUTHPROXY_H
