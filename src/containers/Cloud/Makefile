
CXX = g++
CPPFLAGS += `pkg-config --cflags protobuf grpc libmongocxx`
CXXFLAGS += -std=c++17 -g
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ grpc libmongocxx`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl

CRYPTOFLAGS = -lcrypto -lssl

# just change service name to whatever the name of the proto file was
SERVICENAME = backEndService
GRPCPATH = ../../protos/src/

TPB += $(GRPCPATH)$(SERVICENAME).pb.o
TGRPC += $(GRPCPATH)$(SERVICENAME).grpc.pb.o


all: bes

bes:  main.cc ../Lib/crypto_wrap.o Cloud.cc Cloud.h
	$(CXX) $^ $(LDFLAGS) -o $@ $(CRYPTOFLAGS) $(TPB)  $(TGRPC) $(CPPFLAGS)

clean:
	rm bes

