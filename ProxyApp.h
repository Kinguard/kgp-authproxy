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

	virtual void Startup();
	virtual void Main();
	virtual void ShutDown();

	void SigTerm(int signo);
	void SigHup(int signo);

	virtual ~ProxyApp();
protected:
	AuthProxyPtr proxy;
};

#endif // PROXYAPP_H
