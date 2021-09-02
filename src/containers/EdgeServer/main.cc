#include <iostream>
extern "C" {
    #include "serial_multabe_2.h"
}
#include "EdgeServer.h"


int main(int argc, char **argv) 
{
	py::scoped_interpreter guard{};
	std::string a;
	EdgeServer es(true);
	es.startServer();

	std::cin >> a;
}
