#include <iostream>
#include <unistd.h>

#include "ProxyApp.h"


#include <libutils/Logger.h>

using namespace std;
using namespace Utils;


int main(int argc, char** argv)
{

	int ret = 0;
	try
	{
		ProxyApp app;

		logg.SetLevel(Logger::Debug);

		ret = app.Start(argc, argv);

	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Error << "Caught exception: "<< err.what()<<lend;
	}


	return ret;
}

