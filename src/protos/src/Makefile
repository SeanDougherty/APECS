
CXX = g++
CPPFLAGS += `pkg-config --cflags protobuf grpc`
CXXFLAGS += -std=c++11 
LDFLAGS += -L/usr/local/lib `pkg-config --libs protobuf grpc++ grpc`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl
PROTOC = protoc
GRPC_CPP_PLUGIN = grpc_cpp_plugin
GRPC_CPP_PLUGIN_PATH ?= `which $(GRPC_CPP_PLUGIN)`

# Where the .proto file lives
PROTOS_PATH = ../

vpath %.proto $(PROTOS_PATH)

default: 
	@echo "What to Compile"

all: test backEndService provider edgeServer

test:
	protoc -I ../ --cpp_out=. ../test.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o test.pb.o test.pb.cc
	protoc -I ../ --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../test.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o test.grpc.pb.o test.grpc.pb.cc

backEndService:
	protoc -I ../ --cpp_out=. ../backEndService.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o backEndService.pb.o backEndService.pb.cc
	protoc -I ../ --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../backEndService.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o backEndService.grpc.pb.o backEndService.grpc.pb.cc

edgeServer:
	protoc -I ../ --cpp_out=. ../edgeServer.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o edgeServer.pb.o edgeServer.pb.cc
	protoc -I ../ --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../edgeServer.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o edgeServer.grpc.pb.o edgeServer.grpc.pb.cc

provider:
	protoc -I ../ --cpp_out=. ../provider.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o provider.pb.o provider.pb.cc
	protoc -I ../ --grpc_out=. --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` ../provider.proto
	g++ -std=c++11  `pkg-config --cflags protobuf grpc`  -c -o provider.grpc.pb.o provider.grpc.pb.cc



