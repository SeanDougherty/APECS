
#include "Cloud.h"

Status Cloud::getProvider(ServerContext *context, const ProviderRequest *request,
		ProviderReply *reply) {

	// N_p is the unique identifier for providers. ID_p in APECS protocol 1.
	std::string N_p = request->np();

	// Look up for N_p
	try {
		auto certP = findProviderCertById(N_p);
		if(certP == "0") {
			reply->set_responsecode(403);
			return Status::OK;
		} 

		reply->set_np(N_p);
		reply->set_certp(certP);
		reply->set_responsecode(200);

		return Status::OK;
	} catch (std::exception &e) {
		std::cerr << "[Cloud.cc] " << e.what() << '\n';
		return Status::OK;
	}
} // end getProvider


Status Cloud::registerProvider(ServerContext *context, const CertP *request,
		ProviderID *reply) {

	/* Get the cert from the request, obtain the subject from the cert, hash
	 * the subject to get the providerId, and store the values.
	 */
	std::string certp = request->certp();
	std::string cert_subject = getFieldFromCert(certp,SUBJECT);
	std::cout << "[*] subject: " << cert_subject << std::endl;
	std::string ProviderID = md5hash(cert_subject);
	std::cout << "[*] provider id: " << ProviderID << std::endl;
	std::string expire_time = getFieldFromCert(certp,EXPIRE_TIME);
	std::cout << "[*] Expire time: " << expire_time << std::endl;
	bool is_expired = isExpired(certp);

	storeProviderAndCert(ProviderID,certp);

	try {
		if(is_expired) {
			std::cerr << "[Cloud.cc] Provider Certificate is expired." << '\n';
			reply->set_providerid("");
		} else {
			reply->set_providerid(ProviderID);
		}
		return Status::OK;
	} catch (std::exception &e) {
		std::cout <<"[Cloud.cc] " << e.what() << std::endl;
		reply->set_providerid("Error");
		return Status::OK;
	}
} // end registerProvider


Status Cloud::registerBlackListedToken(ServerContext *context, const UserToken *request,
			BlackListResponse *reply) {
	std::string hashedToken = md5hash(request->token());;
	storeRevocatedToken(hashedToken);
	return Status::OK;
} // end registerBlackListedToken


/* Interface to the data store where Cloud saves this information
 * Back end of data store can be swapped out later.
 */
int Cloud::storeProviderAndCert(std::string providerid, std::string cert) {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		bsoncxx::builder::stream::document document{};

		auto collection = client["CloudDB"]["providerTable"];
		document << "_id" << providerid << "pCert" << cert;

		collection.insert_one(document.view());

		std::cout << "[Cloud.cc] Successfully stored provider." << '\n';
		return 1;
	} catch (std::exception &e) {
		std::cerr << "[Cloud.cc] " << e.what() << std::endl;
		return 0;
	}
} // end storeProviderAndCert


std::string Cloud::findProviderCertById(std::string providerid) {
	try{
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		auto collection = client["CloudDB"]["providerTable"];

		bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(document{} << "_id" << providerid << finalize);

		if(maybe_result) {
			bsoncxx::document::view result_view = maybe_result.value().view();
			bsoncxx::document::element result_element = result_view["pCert"];
			std::string provider_cert = result_element.get_utf8().value.to_string();
			std::cout << "[Cloud.cc] Successfully found provider." << '\n';
			return provider_cert;
		}

		std::cerr << "[Cloud.cc] Error, No Certificate found with that ID" << '\n';
		return "";
	} catch (std::exception &e) {
		std::cerr << "[Cloud.cc] " << e.what() << '\n';
		std::cerr << "[Cloud.cc] Error, querying the database failed in BackEndService::FindProviderCertById" << '\n';
		return "";
	}
} // end findProviderCertById


int Cloud::storeRevocatedToken(std::string revocTokenMD5hash) {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		bsoncxx::builder::stream::document document{};

		auto collection = client["CloudDB"]["revocTable"];
		document << "revocToken" << revocTokenMD5hash;

		collection.insert_one(document.view());

		std::cout << "[Cloud.cc] Successfully stored revocToken." << '\n';
		return 1;
	} catch (std::exception &e) {
		std::cerr << "[Cloud.cc] " << e.what() << '\n';
		std::cerr << "[Cloud.cc] Error storing revocation token in cloudDB" << '\n';
		return 0;
	}
} // end storeRevocatedToken

void Cloud::startServer() {
	std::thread t( [this] { startCloudServer(); } );
	t.detach();
} // end startServer


void Cloud::startCloudServer() {

	//Enable TLS communications
	std::string key = fileToString("../keys/cloud.key");
	std::string crt = fileToString("../keys/cloud.crt");
	std::string ca = fileToString("../keys/ca.crt");

	grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {key.c_str(), crt.c_str()};
	grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY);
	ssl_opts.pem_root_certs = ca;
	ssl_opts.pem_key_cert_pairs.push_back(pkcp);
	//creds = grpc::SslServerCredentials(ssl_opts);
	auto creds = grpc::InsecureServerCredentials();

	// Start the server
	std::string server_address("0.0.0.0:50055");
	ServerBuilder builder;
	builder.AddListeningPort(server_address, creds);
	builder.RegisterService(this);

	std::unique_ptr<Server> server(builder.BuildAndStart());
	std::cout << "Server listening on " << server_address << '\n';

	// Server now waits and answers all requests
	server->Wait();
} // end startCloudServer

std::string Cloud::fileToString(std::string filename) {
	std::ifstream f(filename);
	if(!f.is_open()) {
		std::cerr << "[Cloud.cc] Could not open file: " + filename << '\n';
		exit(0);
	}
	std::stringstream ss;
	ss << f.rdbuf();
	std::string fstr = ss.str();
	f.close();
	return fstr;
}//end fileToString
