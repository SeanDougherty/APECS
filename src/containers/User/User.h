/********************************************************************************
 *
 * User
 *
 * User program to utilize the access control
 *
 * What the user can do:
 *
 *******************************************************************************
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <thread>
#include <chrono>
#include <string>
#include <jwt-cpp/jwt.h>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <bits/stdc++.h>

#include <grpcpp/grpcpp.h>

#include "../../protos/src/edgeServer.grpc.pb.h"
#include "../../protos/src/provider.grpc.pb.h"

#include <pybind11/embed.h>

extern "C" {
    #include "serial_multabe_2.h"
}

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::SslCredentialsOptions;
using grpc::SslCredentials;
using grpc::ChannelCredentials;
using grpc::ChannelArguments;

using providerProto::ProviderService;
using providerProto::UserData;
using providerProto::UserTokenAndSymKey;
using providerProto::RevocRequest;
using providerProto::RevocResponse;
using providerProto::UserCredentials;
using providerProto::NewToken;

using edgeServerProto::EdgeServerService;
using edgeServerProto::UserDataRequest;
using edgeServerProto::DataPayload;
using edgeServerProto::UserServiceRequest;
using edgeServerProto::ServiceResponse;

namespace py = pybind11;

class User {
  public:
	int registerUser();
	int requestData(std::string content_name);
	int requestService();
	int requestRevocation();
	int renewToken();
	int handleDataReceived(DataPayload* reply);
	std::string buildServiceRequest(std::string service_data);
	std::string signServiceRequest(std::string service_request);
	std::string buildRevocRequest();
	std::string signRevocRequest(std::string request);
	std::shared_ptr<grpc::ChannelCredentials> buildClientCredentials(bool isSecure);	
	std::vector<std::string> split(std::string str, std::string sep);
	int stringToFile(std::string data, std::string filename);
	int systemCallEncryptData();
	void setUserCert();
	std::string fileToString(std::string filename);
  private:
	std::string m_symkey;
	std::string m_user_token;
	std::string m_username;
	std::string m_password;
	std::string m_edgeserver_ip = "0.0.0.0:50033";
	std::string m_provider_ip = "0.0.0.0:50077";
	std::string user_cert;
};

