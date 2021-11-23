#ifndef PROXYAPP_H
#define PROXYAPP_H

#include <string>

#include <libutils/Application.h>

#include "AuthProxy.h"

using namespace std;

#define SOCKPATH "/run/kgp/authproxy.socket"

class ProxyApp : public Utils::DaemonApplication
{
public:
	ProxyApp();

	void Startup() override;
	void Main() override;
	void ShutDown() override;

	void SigTerm(int signo);
	void SigHup(int signo);
protected:
	AuthProxyPtr proxy;
};

#endif // PROXYAPP_H
