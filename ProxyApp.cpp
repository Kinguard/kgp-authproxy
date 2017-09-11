
#include "ProxyApp.h"

#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <functional>

#include <unistd.h>

using namespace Utils;
using namespace std::placeholders;

ProxyApp::ProxyApp(): DaemonApplication("opi-authproxy","/var/run","root","root")
{
}


void ProxyApp::SigTerm(int signo)
{
	logg << Logger::Debug << "Got signal "<<signo<<lend;
	this->proxy->ShutDown();
}

void ProxyApp::SigHup(int signo)
{
	// TODO: Perhaps reload any config
}

void ProxyApp::Startup()
{

	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&ProxyApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&ProxyApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&ProxyApp::SigHup, this, _1) );

	try
	{
		// Remove possible old socket
		unlink(SOCKPATH);

		if( ! File::DirExists( File::GetPath( SOCKPATH ) ) )
		{
			File::MkPath( File::GetPath( SOCKPATH ), 0755 );
		}
	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Notice << "Failed to setup directory: " << err.what() << lend;
	}

	proxy = AuthProxyPtr(new AuthProxy(SOCKPATH) );

}


void ProxyApp::Main()
{
	proxy->Run();
}

void ProxyApp::ShutDown()
{

}

ProxyApp::~ProxyApp()
{

}
