#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>
#include <jwt-cpp/jwt.h>
#include <thread>

#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/json.hpp>

#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>

#include <grpcpp/grpcpp.h>

#include "../../protos/src/backEndService.grpc.pb.h"
#include "../Lib/crypto_wrap.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerCredentials;
using grpc::Status;

using grpc::SslCredentials;
using grpc::SslCredentialsOptions;

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


/* Used to store available providers
 * first  => name given for provider by BackEndService
 * second => cert in PEM format for provider
 */
static std::map<std::string,std::string> providerTable;


class Cloud final : public BackEndService::Service {

	public:

		/* Asked by a EdgeServer, when a lookup for a provider is needed.
		 */
		Status getProvider(ServerContext *context, const ProviderRequest *request,
				ProviderReply *reply) override;

		Status registerProvider(ServerContext *context, const CertP *request,
				ProviderID *reply) override ;

		/* Interface to the data store where Cloud saves this information
		 * Back end of data store can be swapped out later.
		 */
		int storeProviderAndCert(std::string providerid, std::string cert);

		std::string findProviderCertById(std::string providerid);

		Status registerBlackListedToken(ServerContext *context, const UserToken *request,
				BlackListResponse *reply) override ;

		int storeRevocatedToken(std::string revocTokenMD5hash);

		void startServer();

		void startCloudServer();

		std::string fileToString(std::string filename);

	private:
		mongocxx::instance inst{};
		std::string m_provider_ip;
		std::string m_edgeserver_ip;
};

