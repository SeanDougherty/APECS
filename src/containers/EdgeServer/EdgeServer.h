#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>
#include <jwt-cpp/jwt.h>
#include <thread>
#include <grpcpp/grpcpp.h>
#include <bits/stdc++.h>

#include "../../protos/src/backEndService.grpc.pb.h"
#include "../../protos/src/edgeServer.grpc.pb.h"
#include "../../protos/src/provider.grpc.pb.h"

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

#include "./caches/include/cache.hpp"
#include "./caches/include/lfu_cache_policy.hpp"

#include <pybind11/embed.h>

extern "C" {
    #include "serial_multabe_2.h"
}

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCredentials;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::SslCredentialsOptions;
using grpc::SslCredentials;
using grpc::ChannelCredentials;
using grpc::ChannelArguments;


using serviceProto::BackEndService;
using serviceProto::ProviderReply;
using serviceProto::ProviderRequest;
using serviceProto::CertP;
using serviceProto::ProviderID;

using edgeServerProto::EdgeServerService;
using edgeServerProto::UserDataRequest;
using edgeServerProto::DataPayload;
using edgeServerProto::UserServiceRequest;
using edgeServerProto::ServiceResponse;

using providerProto::ProviderService;
using providerProto::ProviderDataRequest;
using providerProto::ProviderDataPayload;

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;

namespace py = pybind11;

template <typename Key, typename Value>
using lfu_cache_t =
	typename caches::fixed_sized_cache<Key, Value, caches::LFUCachePolicy<Key>>;


class EdgeServer : public EdgeServerService::Service {

	public:
		EdgeServer(bool isCacheOn);

		/******************************************************************
		 * Client code for Edge Server
		 *****************************************************************/

		/* get provider info from Cloud
		 */
		int getProvider(std::string providerName, std::string *provider_cert);

		/* request data from provider when the cache-miss
		 */
		std::string requestDataFromProvider(std::string content_name, bool *content_found);


		/******************************************************************
		 * Server code for Edge Server
		 *****************************************************************/
		
		/* User requests data through/from EdgeServer
		 */
		Status requestData(ServerContext *context, const UserDataRequest *request, edgeServerProto::DataPayload *reply) override;

		/*
		 */
		Status requestService(ServerContext *context, const UserServiceRequest *request, edgeServerProto::ServiceResponse *reply) override;


		/* thread the startEdgeServer call
		 */
		void startServer();

		/* spin up the server
		 */
		void startEdgeServer();

		/******************************************************************
		 * Helper code for Edge Server
		 *****************************************************************/
	
		std::shared_ptr<grpc::ChannelCredentials> buildClientCredentials(bool isSecure);

		/*
		 */
		std::string fileToString(std::string filename);

		/*
		 */
		int stringToFile(std::string data, std::string filename);

		/*
		 */
		int systemCallDecryptData();

		/*
		 */
		bool verifySignature(std::string service_data, std::string token, std::string signature);

		/*
		 */
		std::string getProviderIdFromToken(std::string user_token);

		/* search back end cache for content by name
		 */
		std::string searchCache(const std::string& content_name, bool *content_found);
		
		/* wrapper to crypto_wrap isExpired function
		 */
		static bool isExpired(const std::string& cert);


		std::string getDataForUser(const std::string& content_name, bool *content_found);
	

		/******************************************************************
		 * Database code for EdgeServer
		 *****************************************************************/


		/* store the provider and cert into the mongo db using the instance of
		 * mongo
		 */
		int storeProviderAndCert(ProviderReply reply);

		/*
		 */
		std::string getProviderCertForId(std::string provider_id);

		/* check the revocation table
		 */
		bool isRevoked(const std::string& token);

		/* store the revoce token in the db
		 */
		int storeRevocatedToken(std::string revocTokenHash);


	private:
		mongocxx::instance inst{};
		bool m_isCacheOn;
		const static int test_ct = 5;
		int elapsed_verifs [test_ct];
		int elapsed_decs [test_ct];
		int elapsed_signverifs [test_ct];
		int elapsed_symdecs [test_ct];
		int service_ct = 0;
		std::string user_cert;
		lfu_cache_t<std::string, std::string> cache{256};
		std::string m_provider_ip =  "0.0.0.0:50077";
		std::string m_cloud_ip = "0.0.0.0:50055";
};
