#include <iostream>

#include "Provider.h"

void usage();

/* start an interactive prompt for the user */
void prompt(Provider *service);

/* Default options to run the Provider
 * If the program is run without args, this will execute
 */
void defaultOptions(Provider *service);


int main(int argc, char **argv) 
{
	Provider service("localhost:50055","GenericProvider");
	defaultOptions(&service);
	exit(0);
	return 0;
}


void defaultOptions(Provider *service) {
	service->startServer();
	prompt(service);
}


void prompt(Provider *service) {

	int reply = 0;
	int opt = 1;
	std::string dataOption;

	while(opt != 0) {
		std::cout << "Options:\n" <<
			"[Server Status] " <<
			((service->m_isServerRunning) ? "Running\n" : "NOT Running\n") <<
			"[0] exit\n" << 
			"[1] start server\n" << 
			"[2] register provider" << std::endl;
			" #> ";
		std::cin >> opt;

		switch(opt) {
			case 0:
				exit(0);
				break;
			case 1:
				service->startServer();
				break;
			case 2:
				service->registerProvider("../keys/provider.crt");
				break;
			default:
				std::cerr << "Unrecognized option." << '\n';
				break;
		} // end switch
	} // end while(opt != 0)
} // end prompt



