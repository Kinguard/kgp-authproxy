
#include "ProxyApp.h"

#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <functional>
#include <syslog.h>

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
	// Divert logger to syslog
	openlog( "opi-authproxy", LOG_PERROR, LOG_DAEMON);
	logg.SetOutputter( [](const string& msg){ syslog(LOG_INFO, "%s",msg.c_str());});
	logg.SetLogName("");

	logg << Logger::Info << "Starting" << lend;

	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&ProxyApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&ProxyApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&ProxyApp::SigHup, this, _1) );

	this->options.AddOption( Option('D', "debug", Option::ArgNone,"0","Debug logging") );

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
	if( this->options["debug"] == "1" )
	{
		logg << Logger::Info << "Increase logging to debug level "<<lend;
		logg.SetLevel(Logger::Debug);
	}
	proxy->Run();
}

void ProxyApp::ShutDown()
{

}

ProxyApp::~ProxyApp()
{

}
