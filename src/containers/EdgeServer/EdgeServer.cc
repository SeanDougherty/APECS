#include "EdgeServer.h"
#include "../Lib/crypto_wrap.hpp"

EdgeServer::EdgeServer(bool isCacheOn) {
	this->m_isCacheOn = isCacheOn;
//	constexpr std::size_t CACHE_SIZE = 256;
//	lfu_cache_t<std::string, std::string> cache(CACHE_SIZE);
}

/******************************************************************
 * Client code for Edge Server
 *****************************************************************/


int EdgeServer::getProvider(std::string providerName, std::string *provider_cert) {

	//Enable TLS Communications
        auto creds = buildClientCredentials(false);
        grpc::ChannelArguments channel_args = ChannelArguments();
        channel_args.SetSslTargetNameOverride("cloud.foo");
	std::unique_ptr<BackEndService::Stub> stub_(BackEndService::NewStub(
				grpc::CreateCustomChannel(this->m_cloud_ip,creds,channel_args)));

	//Build Request
	ProviderRequest request;
	request.set_np(providerName);
	
	//Build necessary variables
	ProviderReply reply;
	ClientContext context;

	//Call API
	Status status = stub_->getProvider(&context, request, &reply);
	
	//Handle response
	if (status.ok()) {
		std::cout << "[*] response code: " << reply.responsecode() << std::endl;
	} else {
		std::cerr << "Error" << std::endl;
	}


	std::cout << "Greeter received: " << reply.responsecode() << std::endl;
	std::cout << "found the cert: \n" << reply.certp() << std::endl;
	
	//On success, store provider info
	if(reply.responsecode() == 200){
		storeProviderAndCert(reply);
		*provider_cert = reply.certp();
		return 1;
	}
	return 0;
}// end getProvider


std::string EdgeServer::requestDataFromProvider(std::string content_name, bool *content_found) {

	//Enable TLS Communications
        auto creds = buildClientCredentials(false);
        grpc::ChannelArguments channel_args = ChannelArguments();
        channel_args.SetSslTargetNameOverride("provider.foo");
	std::unique_ptr<ProviderService::Stub> stub_(ProviderService::NewStub(
				grpc::CreateCustomChannel(this->m_provider_ip,creds,channel_args)));
	
	//Build Request
	ProviderDataRequest request;
	request.set_content_name(content_name);
	
	//Build necessary variables
	ProviderDataPayload reply;
	ClientContext context;

	//Call API
	Status status = stub_->requestDataFromProvider(&context, request, &reply);
	
	//Handle response
	if (status.ok()) {
//		std::cout << "[*] response code: " << reply.response_code() << std::endl;
	} else {
//		std::cout << "Error when calling EdgeServer::requestDataFromProvider" << std::endl;
	}


	if(reply.response_code() == 200) {
		*content_found = true;
		return reply.data();
	} else {
		std::cout << "unable to retrieve data, error given: \n" << reply.msg() << std::endl;
		std::cout << "[*] response code: " << reply.response_code() << std::endl;
		return "";
	}
}//end requestDataFromProvider

/******************************************************************
 * Server code for Edge Server
 *****************************************************************/

Status EdgeServer::requestData(ServerContext *context, const UserDataRequest *request, DataPayload *reply) {
	bool status;
	bool tls_enabled = false;
	try {

		/* Extract fields from user_token */
		std::string token = request->user_token();
		auto decoded = jwt::decode(token);
		auto x = decoded.get_payload_claims();
		auto claim = x.find("provider_id");
		if (claim == x.end()) {
			std::cerr << "Error getting provider_id from token" << std::endl;
		}
		std::string provider_id = claim->second.as_string();

		/* Use the provider public key to verify the token */
		std::string certp = getProviderCertForId(provider_id);
		
		if (certp == "error") {
			getProvider(provider_id, &certp);
		}


		std::string rsa_pub = getRSAPubFromCert(certp);

		std::string client_cert;

		/* check the revocation table */
		status = isRevoked(request->user_token());

		/* verify token against provider pubkey */
		status = verifyToken(request->user_token(), rsa_pub);
	
		status = verifySignature(request->content_name(), token, request->signature());
	
		if(status) {
		//	std::cout << "[*] Token is valid" << std::endl;
		} else {
		//	std::cout << "[!] INVALID TOKEN" << std::endl;
		}
		
		/* LAST STEP */
		/* search cache and provider for data, if not found, return */
		std::string content = "";
		bool content_found = false;
		if (this->m_isCacheOn){
			try {
				content = cache.Get(request->content_name());
				content_found = true;
			} catch (std::exception &e) {
				content = getDataForUser(request->content_name(), &content_found);
				if (content_found)
					cache.Put(request->content_name(), content);
			}
		}

		if(!content_found) {
			reply->set_data("");
			reply->set_msg("Unable to retrieve data");
			reply->set_response_code(404);
			return Status::OK;
		}


		/* set the data to return to the User */
		reply->set_data(content);

		/* set the remaining status fields */
		reply->set_msg("able to retrieve data");
		reply->set_response_code(200);

		return Status::OK;
	} catch (std::exception &e) {
		std::cout << "Error in EdgeServer::requestData" << std::endl;
		std::cout << e.what() << std::endl;
		reply->set_msg(e.what());
		return Status::OK;
	}
}
		


Status EdgeServer::requestService(ServerContext *context, const UserServiceRequest *request, ServiceResponse *reply) {
	bool status;
	bool tls_enabled = false;
	try {

		auto verif_start = std::chrono::high_resolution_clock::now();

		std::string token = request->user_token();
		auto decoded = jwt::decode(token);
		auto x = decoded.get_payload_claims();
		auto claim = x.find("provider_id");
		if (claim == x.end()) {
			std::cerr << "Error getting provider_id from token" << std::endl;
		}
		std::string provider_id = claim->second.as_string();

		/* Use the provider public key to verify the token */
		std::string certp = getProviderCertForId(provider_id);
		
		if (certp == "error") {
			getProvider(provider_id, &certp);
		}

		std::string rsa_pub = getRSAPubFromCert(certp);

		std::string client_cert;
		std::string signature = request->signature();
		std::string service_data = request->service_data();

		/* check the revocation table */
		status = isRevoked(request->user_token());

		/* verify token against provider pubkey */
		status = verifyToken(request->user_token(), rsa_pub);

		auto verif_stop = std::chrono::high_resolution_clock::now();
		auto signverif_start = std::chrono::high_resolution_clock::now();

		status = verifySignature(service_data, token, signature);
		
		auto signverif_stop = std::chrono::high_resolution_clock::now();
		if(status) {
			//std::cout << "[*] Token is valid" << std::endl;
		} else {
			//std::cout << "[!] INVALID TOKEN" << std::endl;
		}
		/* LAST STEP */
		/* search cache and provider for data, if not found, return */
		py::module_ mabe = py::module_::import("mabe");
		struct SetupVars setupvars = {(unsigned char *) request->y().data(), (unsigned char *) request->g2().data(), (unsigned char *) request->t_1a1().data(), (unsigned char *) request->t_1a2().data(), (unsigned char *) request->t_2a2().data(), (unsigned char *) request->t_2a3().data(), (unsigned char *) request->t_3a1().data(), (unsigned char *) request->t_3a3().data(), (unsigned char *) request->s_1_1_u1().data(), (unsigned char *) request->g1().data(), (unsigned char *) request->coeff_auth1_u1_0().data(), (unsigned char *) request->coeff_auth1_u1_1().data(), (unsigned char *) request->s_1_2_u1().data(), (unsigned char *) request->s_2_2_u1().data(), (unsigned char *) request->coeff_auth2_u1_0().data(), (unsigned char *) request->coeff_auth2_u1_1().data(), (unsigned char *) request->s_2_3_u1().data(), (unsigned char *) request->coeff_auth3_u1_0().data(), (unsigned char *) request->coeff_auth3_u1_1().data(), (unsigned char *) request->s_3_1_u1().data(), (unsigned char *) request->s_3_3_u1().data(), (unsigned char *) request->d_u1().data(), (unsigned char *) request->temp_1_gt().data(), (unsigned char *) request->temp_1_zr().data(), (unsigned char *) request->temp_2_zr().data(), (unsigned char *) request->e_g1g2().data()  };
		struct EncryptVars encryptvars = { (unsigned char *) request->e_0().data(), (unsigned char *) request->e_1().data(), (unsigned char *) request->c_1_1().data(), (unsigned char *) request->c_1_2().data(), (unsigned char *) request->c_2_2().data(), (unsigned char *) request->c_2_3().data(), (unsigned char *) request->c_3_1().data(), (unsigned char *) request->c_3_3().data(), (unsigned char *) request->msg().data(), (unsigned char *) request->s().data(), (unsigned char *) request->l1_0_auth1().data(), (unsigned char *) request->l2_0_auth1().data(), (unsigned char *) request->l2_0_auth2().data(), (unsigned char *) request->l3_0_auth2().data(), (unsigned char *) request->l1_0_auth3().data(), (unsigned char *) request->l3_0_auth3().data() };
		auto dec_start = std::chrono::high_resolution_clock::now();
    c_decrypt(&setupvars, &encryptvars);
	  //Load setup_dict into pyObject
		auto dec_stop = std::chrono::high_resolution_clock::now();
		auto symdec_start = std::chrono::high_resolution_clock::now();

		py::object result = mabe.attr("decryptPayload2")("12345678901234567890",  service_data);
		std::string decrypted_msg = result.cast<std::string>();
		auto symdec_stop = std::chrono::high_resolution_clock::now();

		auto verif_duration = std::chrono::duration_cast<std::chrono::microseconds>(verif_stop-verif_start);
		auto signverif_duration = std::chrono::duration_cast<std::chrono::microseconds>(signverif_stop-signverif_start);
		auto dec_duration = std::chrono::duration_cast<std::chrono::microseconds>(dec_stop-dec_start);
		auto symdec_duration = std::chrono::duration_cast<std::chrono::microseconds>(symdec_stop-symdec_start);
		auto verif_micro = int(verif_duration.count());
		auto signverif_micro = int(signverif_duration.count());
		auto dec_micro = int(dec_duration.count());
		auto symdec_micro = int(symdec_duration.count());
		int idx = this->service_ct;
		this->elapsed_verifs[idx] = verif_micro;
		this->elapsed_signverifs[idx] = signverif_micro;
		this->elapsed_decs[idx] = dec_micro;
		this->elapsed_symdecs[idx] = symdec_micro;
		this->service_ct += 1;
   		if (idx == this->test_ct-1) {
			std::string verifs = "";
			std::string signverifs = "";
			std::string decs = "";
			std::string symdecs = "";
			for (int i=0; i < idx; i++) {
				if(i < this->test_ct){
					verifs = verifs + std::to_string(this->elapsed_verifs[i]) + ", ";
					signverifs = signverifs + std::to_string(this->elapsed_signverifs[i]) + ", ";
					decs = decs + std::to_string(this->elapsed_decs[i]) + ", ";
					symdecs = symdecs + std::to_string(this->elapsed_symdecs[i]) + ", ";
				} else {
					verifs = verifs + std::to_string(this->elapsed_verifs[i]);
					signverifs = signverifs + std::to_string(this->elapsed_signverifs[i]);
					decs = decs + std::to_string(this->elapsed_decs[i]);
					symdecs = symdecs + std::to_string(this->elapsed_symdecs[i]);
				}
			}
			stringToFile(verifs, "verif_runtimes.csv");
			stringToFile(decs, "dec_runtimes.csv");
			stringToFile(symdecs, "symdec_runtimes.csv");
			stringToFile(signverifs, "signverif_runtimes.csv");
		}


		/* set the remaining status fields */
		reply->set_result("Success!");

		return Status::OK;
	} catch (std::exception &e) {
		reply->set_result(e.what());
	} 
		return Status::OK;
}

bool EdgeServer::verifySignature(std::string service_data, std::string token, std::string signature){
	auto decoded = jwt::decode(token);
	auto claims = decoded.get_payload_claims();
	auto u_id = claims.find("user_id");
	std::string token_piece = std::string(u_id->second.as_string());
	std::string service_request = service_data + "|" + token_piece;
	std::string pub_from_cert = getRSAPubFromToken(token);
	return verifySig(pub_from_cert, service_request, signature);
}

void EdgeServer::startServer() {
	std::thread t( [this] { startEdgeServer(); } );
	t.detach();
}

void EdgeServer::startEdgeServer() {

        //Enable TLS communications
        std::string key = fileToString("../keys/edgeserver.key");
        std::string crt = fileToString("../keys/edgeserver.crt");
        std::string ca = fileToString("../keys/ca.crt"); 
        grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp ={key,crt};      
        grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY);
        ssl_opts.pem_root_certs=ca;
        ssl_opts.pem_key_cert_pairs.push_back(pkcp);
        //std::shared_ptr<ServerCredentials> creds;
	//creds = grpc::SslServerCredentials(ssl_opts);
	auto creds = grpc::InsecureServerCredentials();

	// Start the server
        std::string server_address("0.0.0.0:50033");
        ServerBuilder builder;
        builder.AddListeningPort(server_address,creds);
        builder.RegisterService(this);

        std::unique_ptr<Server> server(builder.BuildAndStart());
        std::cout << "Server listening on " << server_address << std::endl;

	this->user_cert = fileToString("../keys/user.crt");

        // Server now waits and answers all requests
        server->Wait();

}

/******************************************************************
 * Helper code for EdgeServer
 *****************************************************************/

std::shared_ptr<grpc::ChannelCredentials> EdgeServer::buildClientCredentials(bool isSecure) {

        if (!isSecure)
                return std::shared_ptr<grpc::ChannelCredentials>(grpc::InsecureChannelCredentials());

        std::string key = fileToString("../keys/edgeserver.key");
        std::string crt = fileToString("../keys/edgeserver.crt");
        std::string ca = fileToString("../keys/ca.crt");
        grpc::SslCredentialsOptions tlsOpts;
        tlsOpts.pem_cert_chain = crt;
        tlsOpts.pem_private_key = key;
        tlsOpts.pem_root_certs = ca;
        return std::shared_ptr<grpc::ChannelCredentials>(grpc::SslCredentials(tlsOpts));
}// end buildClientCredentials


std::string EdgeServer::fileToString(std::string filename) {
        std::ifstream f(filename);
        if(!f.is_open()) {
                std::cout << "Could not open file: " + filename << std::endl;
                exit(0);
        }
        std::stringstream ss;
        ss << f.rdbuf();
        std::string fstr = ss.str();
        f.close();
        return fstr;
} // end fileToString


int EdgeServer::stringToFile(std::string data, std::string filename){
	std::ofstream f(filename);
	f << data;
	f.close();
	return 0;
} // end stringToFile

int EdgeServer::systemCallDecryptData(){
	std::string system_call_string = "python3 improvedmultiabe.py d";
	const char *command = system_call_string.c_str();
	system(command);
}


std::string EdgeServer::getProviderIdFromToken(std::string user_token) {	
	auto decoded = jwt::decode(user_token);
	auto p_id = decoded.get_payload_claims().find("provider_id");
	return std::string(p_id->second.as_string());
}//end getProviderIdFromToken

std::string EdgeServer::searchCache(const std::string& content_name, bool *content_found) {
	*content_found = true;
	return std::string("temp cache data");
}//end searchCache

bool EdgeServer::isExpired(const std::string& cert) {
	return true;
}//end isExpired

std::string EdgeServer::getDataForUser(const std::string& content_name, bool *content_found) {

	std::string dataToReturn = "";
	/* If cache is enable search cache first */
	dataToReturn = requestDataFromProvider(content_name, content_found);

	/* if content is not found in cache or provider, set to false */
	return dataToReturn;
}//end getDataForUser


/******************************************************************
 * Database code for EdgeServer
 *****************************************************************/

int EdgeServer::storeProviderAndCert(ProviderReply reply) {
	try {
		//Create database client
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		//Create document for inserting/editing database
		bsoncxx::builder::stream::document document{};
		
		//Specify location in database
  		auto collection = client["EdgeServerDB"]["providerTable"];
		
		//Create entry
		document << "_id" << reply.np() << "pCert" << reply.certp();

		//Insert entry
		collection.insert_one(document.view());

		std::cout << "Successfully stored provider!" << std::endl;
		return 1;
	} catch (std::exception &e) {
		std::cout << e.what() << std::endl;
		return 0;
	}

}// end storeProviderAndCert

std::string EdgeServer::getProviderCertForId(std::string provider_id) {
        try {
		//Create database client
                static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);
		
		//Specify location in database
                auto collection = client["EdgeServerDB"]["providerTable"];

		//Lookup entry
                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
                                document{} <<
                                "_id" << provider_id
                                << finalize);

		//If found, handle
                if(maybe_result) {
			bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["pCert"];
                        std::string provider_cert = result_element.get_utf8().value.to_string();
                        //std::cout << "Successfully found Provider Cert!" << std::endl;
                        return provider_cert;
                }
		
		//Improve handling of "not found" condition
                //std::cout << "No token found" << std::endl;
                return "error";
        } catch (std::exception &e) {
                std::cout << e.what() << std::endl;
                std::cout << "Error searching for provider_id in EdgeServer::getProviderKeyFromToken" << std::endl;
                return "error";
        }
}//end getProviderCertForId

bool EdgeServer::isRevoked(const std::string& token) {
	try {
		//Create database client
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

		//Specify location in database
                auto collection = client["EdgeServerDB"]["revocTable"];

		//Lookup entry
                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
                                document{} <<
                                "revocToken" << token
                                << finalize);

		//If found, handle
                if(maybe_result) {
                        std::cout << "this token is revoked!" << std::endl;
			return true;
                }

                //std::cout << "No token found" << std::endl;
                return false;
        } catch (std::exception &e) {
                std::cout << e.what() << std::endl;
                std::cout << "Error verifying if token was revoked. Preventing data request as a precaution" << std::endl;
                return true;
        }
}//end isRevoked

int EdgeServer::storeRevocatedToken(std::string revocTokenHash) {
	try {
		//Create database client	
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		//Create document for inserting/editing database
		bsoncxx::builder::stream::document document{};

		//Specify location in database
		auto collection = client["EdgeServerDB"]["revocTable"];

		//Create entry
		document << "revocToken" << revocTokenHash;

		//Insert entry
		collection.insert_one(document.view());

		std::cout << "Successfully stored revoked token!" << std::endl;
		return 1;
	} catch (std::exception &e) {
		std::cout << e.what() << std::endl;
		std::cout << "error while attempting to call EdgeServer::storeRevocatedToken" << std::endl;
	}
}
