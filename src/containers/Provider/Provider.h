/********************************************************************************
 *
 * Provider
 *
 *******************************************************************************
 */
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <thread>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/stdx/string_view.hpp>
#include <bsoncxx/json.hpp>
#include <jwt-cpp/jwt.h>
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

/* Include grpc code */
#include "../../protos/src/backEndService.grpc.pb.h"
#include "../../protos/src/provider.grpc.pb.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCredentials;
using grpc::Status;

using grpc::Channel;
using grpc::ClientContext;
using grpc::ChannelCredentials;
using grpc::ChannelArguments;
using grpc::SslCredentialsOptions;
using grpc::SslCredentials;

using providerProto::ProviderService;
using providerProto::UserData;
using providerProto::UserTokenAndSymKey;
using providerProto::ProviderDataRequest;
using providerProto::ProviderDataPayload;
using providerProto::RevocRequest;
using providerProto::RevocResponse;
using providerProto::UserCredentials;
using providerProto::NewToken;

using serviceProto::BackEndService;
using serviceProto::ProviderReply;
using serviceProto::ProviderRequest;
using serviceProto::CertP;
using serviceProto::ProviderID;
using serviceProto::UserToken;
using serviceProto::BlackListResponse;

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;
using bsoncxx::stdx::string_view;

class Provider : public ProviderService::Service {

	public:

		/* Constructor:
		 * pass in any needed info at the beginning for the Provider
		 */
		Provider(std::string cloud_addr, std::string provider_name);


		/******************************************************************
		 ******************************************************************
		 * Server code for Provider
		 ******************************************************************
		 *****************************************************************/

		/* start and thread the server */
		void startServer();

		/* Start the provider portion of the code
		 * This runs the Provider server, to handle grpc requests from and
		 * clients to the Provider
		 */
		void startProviderServer();

		/* End point for client to register a user with the Provider
		 * User sends credentials, and Provider will return a symkey and token
		 * for the user to use.
		 */
		Status registerUser(ServerContext *context, const UserData *request,
			UserTokenAndSymKey *reply) override;

		/* Request a piece of data from the Provider
		 */
		Status requestDataFromProvider(ServerContext *context, const ProviderDataRequest *request, ProviderDataPayload *reply) override;

		/*
		 */
		Status requestRevocation(ServerContext *context, const RevocRequest *request, RevocResponse *reply) override;

	
		/*
		 */
		Status renewToken(ServerContext *context, const UserCredentials *request, NewToken *reply) override;

		/*
		 */
		std::string getTokenForUserId(std::string u_id);

		/*
		 */
		std::string getUserIdFromToken(std::string user_token);

		/*
		 */
		std::string generateToken(std::string user_id, std::string cert);

		/*
		 */
		std::string getCertForUserId(std::string u_id);

		/*
		 */
		int removeUserForUserId(std::string u_id);

		bool verifyRevocRequestSignature(std::string revoc_request, std::string request_signature, std::string stored_cert);

		/*
		 */
		std::string getContentForContentName(std::string content_name);

		/* read in a file as a string and return that string.
		 */
		std::string fileToString(std::string filename);

		/******************************************************************
		 ******************************************************************
		 * Client code for Provider
		 ******************************************************************
		 *****************************************************************/

		/* call client code of BackEndService ( Cloud to register )
		 * connection should be closed when this function call is finished.
		 */
		int registerProvider(const std::string& certp);

		int notifyBlackListedToken(std::string uToken);

		/******************************************************************
		 ******************************************************************
		 * Helper code for Provider
		 ******************************************************************
		 *****************************************************************/

		int storeProviderId(std::string providerid);

		std::string getProviderId();

		// Provider stores user data
		int storeUserData(const UserData *request, std::string token, std::string userId);

		std::shared_ptr<grpc::ChannelCredentials> buildClientCredentials(bool isSecure);

		bool verifyUserCredentials(std::string username, std::string password);

		std::string getUserIdForUsername(std::string username);

		int getAccessLevelForContentName(std::string name);

		bool updateUserToken(std::string u_id, std::string new_token);

		bool updateCertForUserId(std::string u_id, std::string client_cert);

		int buildContentDatabase();

		int buildKeyDatabase();

		std::string getAccessKeyForLevel(int level);

		std::string encryptDataForAccessLevel(std::string content_name, std::string data);

	public:
		bool m_isServerRunning;

	private:
		std::string m_cloud_address;
		std::string m_providerID;
		std::string rsa_priv;
		std::string rsa_pub;
		std::string m_cloud_ip;
		std::string m_edgeserver_ip;

		mongocxx::instance inst{};

};

