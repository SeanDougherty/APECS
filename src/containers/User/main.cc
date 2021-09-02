#include <iostream>
extern "C" {
    #include "serial_multabe_2.h"
}
#include "User.h"

void usage();

/* start an interactive prompt for the user */
void prompt(User *user);

/* Use as default run options for user */
void defaultOptions(User *user);


int main(int argc, char **argv) 
{
	py::scoped_interpreter guard{};
	User u;
	u.setUserCert();
	/* check if should run with defaultOptions */
	if(argc < 2) { 
		std::cout << "[!] No arg, Running defaultOptions" << std::endl;
		usage();
		defaultOptions(&u);
		exit(0);
	}

	/* check options and perform single operation */
	if( (std::string("--register-user").compare(argv[1])) == 0) {
		int reply = u.registerUser();
		std::cout << "reply for register: " << reply << std::endl;
	} else if((std::string("--request-data").compare(argv[1])) == 0) {
		int reply_three = u.requestData("Mandalorian");
		std::cout << "reply for data: " << reply_three << std::endl;
	} else if((std::string("--prompt").compare(argv[1])) == 0) {
		prompt(&u);	
	} else {
		std::cout << "[!] Option not recognized!" << std::endl;
	}


	//int reply_two = u.requestRevocation();
	//std::cout << "reply for revoc: " << reply_two << std::endl;
	return 0;
}


void defaultOptions(User *user) {
	//std::cout << "No default options right now" << std::endl;
	user->registerUser();
}


void prompt(User *user) {

	int reply = 0;
	int opt = 1;
	std::string dataOption;
	
	while(opt != 0) {
		std::cout << "Options:\n" <<
			"[1] register user\n" << 
			"[2] request data\n" << 
			"[3] request revoc\n" <<
			"[4] request service\n" <<
			"[5] placeholder\n" <<
			"[0] exit\n" << 
			" #> ";

		std::cin >> opt;

		switch(opt) {
			case 0:
				exit(0);
				break;
			case 1:
				reply = user->registerUser();
				break;
			case 2:
				std::cout << "[?] What data?\n";
				std::cin >> dataOption;
				reply = user->requestData(dataOption);
				break;
			case 3:
				reply = user->requestRevocation();
				break;
			case 4:
				reply = user->requestService();
				break;
			case 5:
                {
                struct SetupVars* setupvars = c_setup();
                std::cout << "this happened" << std::endl;
                struct EncryptVars* encryptvars = c_encrypt(setupvars);
                std::cout << "then this happened" << std::endl;
                int resu = c_decrypt(setupvars, encryptvars);
                std::cout << "finally this happened" << std::endl;

				//reply = user->placeholder();
				break;
                }
			default:
				std::cout << "What??" << std::endl;
				break;
		} // end switch
	} // end while ( loop for user input )
}


void usage() {
	std::cout << "usage:\n" <<
		"--register-user\n" <<
		"--request-data\n" <<
		"--prompt\n" <<
		"OR run with no options to run defaultOptions" << 
		std::endl;
}


