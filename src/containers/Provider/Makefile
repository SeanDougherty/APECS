
CXX = g++
CPPFLAGS += `pkg-config --cflags protobuf grpc libmongocxx`
CXXFLAGS += -std=c++17 -g 
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ grpc libmongocxx`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl

CRYPTOFLAGS = -lcrypto -lssl

# just change service name to whatever the name of the proto file was
SERVICENAME = backEndService
SERVICENAMETWO = provider
GRPCPATH = ../../protos/src/

TPB += $(GRPCPATH)$(SERVICENAME).pb.o
TGRPC += $(GRPCPATH)$(SERVICENAME).grpc.pb.o

TPBTWO += $(GRPCPATH)$(SERVICENAMETWO).pb.o
TGRPCTWO += $(GRPCPATH)$(SERVICENAMETWO).grpc.pb.o


all: provider

provider:  main.cc Provider.cc Provider.h ../Lib/crypto_wrap.o
	$(CXX) $^ $(LDFLAGS) -o $@ $(CRYPTOFLAGS) $(TPB)  $(TGRPC) $(TPBTWO) $(TGRPCTWO) $(CPPFLAGS)

clean:
	rm provider

