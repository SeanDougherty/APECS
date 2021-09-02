
CXX = g++
CPPFLAGS += `pkg-config --cflags protobuf grpc libmongocxx`
CXXFLAGS += -std=c++17 -g 
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ grpc libmongocxx`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl -g -w -lpbc -lgmp -I /usr/local/include/pbc -Wall -Werror -fPIC -O4

CRYPTOFLAGS = -lcrypto -lssl

PYBIND = `python3 -m pybind11 --includes`
PYBINDTWO = `python3-config --extension-suffix`

# just change service name to whatever the name of the proto file was
SERVICENAME = backEndService
SERVICENAMETWO = edgeServer
SERVICENAMETHREE = provider
GRPCPATH = ../../protos/src/

TPB += $(GRPCPATH)$(SERVICENAME).pb.o
TGRPC += $(GRPCPATH)$(SERVICENAME).grpc.pb.o

TPBTWO += $(GRPCPATH)$(SERVICENAMETWO).pb.o
TGRPCTWO += $(GRPCPATH)$(SERVICENAMETWO).grpc.pb.o

TPBTHREE += $(GRPCPATH)$(SERVICENAMETHREE).pb.o
TGRPCTHREE += $(GRPCPATH)$(SERVICENAMETHREE).grpc.pb.o

all: es

es:  main.cc EdgeServer.cc EdgeServer.h ../Lib/crypto_wrap.o serial_multabe_2.c
	$(CXX) $^ $(LDFLAGS) -o $@ $(CRYPTOFLAGS) $(TPB)  $(TGRPC) $(TPBTWO) $(TGRPCTWO) $(TPBTHREE) $(TGRPCTHREE) $(CPPFLAGS) $(PYBIND) $(shell python3-config --libs)

clean:
	rm es


