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
		logg.SetLevel(Logger::Info);

		ProxyApp app;

		ret = app.Start(argc, argv);

	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Error << "Caught exception: "<< err.what()<<lend;
		ret = 1;
	}


	return ret;
}

