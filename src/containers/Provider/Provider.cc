
#include "Provider.h"
#include "../Lib/crypto_wrap.hpp"


Provider::Provider(std::string cloud_addr, std::string provider_name) {
	this->m_cloud_address = cloud_addr;
	this->m_providerID = provider_name;
	this->m_isServerRunning = false;
}


void Provider::startServer() {
	if(m_isServerRunning) {
		std::cout << "[!] Server is already running!" << std::endl;
		return;
	}
	std::thread t( [this] { startProviderServer(); } );
	t.detach();
	this->m_isServerRunning = true;
}


void Provider::startProviderServer() {
	std::string server_address("0.0.0.0:50077");
	//Provider service;
	ServerBuilder builder;

	//Enable TLS communications
	std::string key = fileToString("../keys/provider.key");
	std::string crt = fileToString("../keys/provider.crt");
	std::string ca = fileToString("../keys/ca.crt");
	grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp ={key.c_str(),crt.c_str()};	
	grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_CLIENT_CERTIFICATE_BUT_DONT_VERIFY);
	ssl_opts.pem_root_certs=ca;
	ssl_opts.pem_key_cert_pairs.push_back(pkcp);
	//std::shared_ptr<ServerCredentials> creds;
	//creds = grpc::SslServerCredentials(ssl_opts);

	auto creds = grpc::InsecureServerCredentials();	
	builder.AddListeningPort(server_address,creds);
	builder.RegisterService(this);

	std::unique_ptr<Server> server(builder.BuildAndStart());
	std::cout << "Server listening on " << server_address << std::endl;

	std::cout << "Building Content Database..." << std::endl;
	buildContentDatabase();
	std::cout << "Building Key Database..." << std::endl;
	buildKeyDatabase();
	server->Wait();
}

Status Provider::registerUser(ServerContext *context, const UserData *request,
	UserTokenAndSymKey *reply) {

	bool tls_enabled = false;

	std::string clientCert;

	//Retrieve TLS cert
	if (tls_enabled) {
		clientCert = context->auth_context()->FindPropertyValues("x509_pem_cert").front().data();
	}
	else {
		clientCert = fileToString("../keys/user.crt");
	}


	//std::string userPubKey = getRSAPubFromCert(clientCert);

	int al = request->access_level();

	//std::cout << clientCert << std::endl;
	std::string userId = genRandString(32);

	/* create and sign the token with the user supplied info here */
	std::string token = generateToken(userId, request->certu());
	
	/* Encrypt the symmetric key with the user public key here 
	 * Setting the symkey is actually setting the encrypted symkey
	 * that only the user should be able to decrypt using their private key
	 */
	std::string keys = "";
	std::string userPubKey = fileToString("../../keys/www.example.com.pubkey.pem");	

	int encrypt_len = 0;
	int encrypt_len_tot = 0;
	for (int i = 0; i < al+1; i++) {
		std::string key = getAccessKeyForLevel(i);
		keys += (key + " ");
	}

	std::string key_fin = encryptSymKeyWithPubKey(userPubKey, keys, &encrypt_len);

	//  std::cout << "[debug] symkey_len: " << encrypt_len_tot << std::endl;
	//  std::cout << "[debug] symkey: " << keys << std::endl;
	//  std::cout << "[debug] token: " << token << std::endl;

	reply->set_token(token);


	/* symkey is encrypted, and transfered as 'bytes' data type,
	* since it's bytes, the final encrypted length will be needed to decrypt the
	* key
	*/ 
	reply->set_symkey(key_fin);
	reply->set_symkey_length(encrypt_len);

	try {
		storeUserData(request, token, userId);
	} catch (std::exception &e) {
		std::cout << "[Provider.cc] " << e.what() << '\n';
	}
	return Status::OK;
} // end registerUser

Status Provider::requestDataFromProvider(ServerContext *context, const ProviderDataRequest *request, ProviderDataPayload *reply) {
	std::string content_name = request->content_name();
	std::string data = getContentForContentName(content_name);
	int access_level = getAccessLevelForContentName(content_name);
	std::string encrypted_data =  encryptDataForAccessLevel(content_name, data);
	reply->set_data(encrypted_data);
	reply->set_access_level(access_level);
	reply->set_response_code(200);
	reply->set_msg("was able to find the content for: " + content_name);
	return Status::OK;
} // end requestDataFromProvider

Status Provider::requestRevocation(ServerContext *context, const RevocRequest *request, RevocResponse *reply) {
	bool tls_enabled = false;
	std::string client_cert;
	//Retrieve TLS certificate
  if (tls_enabled) {
		client_cert = context->auth_context()->FindPropertyValues("x509_pem_cert").front().data();
	} else {
		client_cert = fileToString("../keys/user.crt");
	}

	//Retrieve user_token
	std::string user_token = request->user_token();
	std::string certp = fileToString("../keys/provider.crt");
	std::string provider_pub = getRSAPubFromCert(certp);

	bool isVerified = false;
	
	//Verify user identity
	isVerified = verifyTLS(user_token, client_cert);
	
	//Verify token is from provider
	isVerified = verifyToken(user_token, provider_pub);

	//Handle verification
	if (isVerified) {
		std::string u_id = getUserIdFromToken(user_token);
		notifyBlackListedToken(user_token);
		removeUserForUserId(u_id);
		reply->set_msg("revocation successful");
		reply->set_response_code(200);
	} else {
		reply->set_msg("unable to revoc token");
		reply->set_response_code(403);
	}
		return Status::OK;
} // end requestRevocation

Status Provider::renewToken(ServerContext *context, const UserCredentials *request, NewToken *reply) {
	
	bool tls_enabled = false;
	std::string client_cert;
	
	//Retrieve TLS certificate
	if (tls_enabled) {
		client_cert = context->auth_context()->FindPropertyValues("x509_pem_cert").front().data();  
	} else {
		client_cert = fileToString("../keys/user.crt");
	}
	//Retrieve Username/Password from request
	std::string username = request->username();
	std::string password = request->password();
	
	//Verify credentials
	bool userVerified = verifyUserCredentials(username, password);

	if (!userVerified)
		return Status::OK;

	//Retrieve u-cert from db
	std::string u_id = getUserIdForUsername(username);
	std::string storedCert = getCertForUserId(u_id);

	//compare TLS cert to u-cert
	int certsEqual = storedCert.compare(client_cert);

	if (certsEqual != 0) {
		updateCertForUserId(u_id, client_cert);
	}
	
	//Generate new user token
	std::string new_token = generateToken(u_id, client_cert);
	
	//Update stored user token
	bool tokenUpdated = updateUserToken(u_id, new_token);

	if (!tokenUpdated)
		return Status::OK;

	//Load new token into reply
	reply->set_user_token(new_token);
	
	return Status::OK;
}



std::string Provider::getTokenForUserId(std::string u_id) {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["userTable"];

                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
				document{} << 
				"_id" << bsoncxx::oid{bsoncxx::stdx::string_view{u_id}}
				<< finalize);

                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["token"];
                        std::string token = result_element.get_utf8().value.to_string();
                        std::cout << "Successfully found user token!" << std::endl;
                        return token;
                }

                std::cerr << "[Provider.cc] Error, No User found with that ID" << '\n';
                return "0";
	} catch (std::exception &e) {
		std::cerr << "[Provider.cc] " << e.what() << '\n';
		std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getTokenForUserId" << '\n';
		return "";
	}
}

std::string Provider::getUserIdFromToken(std::string user_token) {
        auto decoded = jwt::decode(user_token);
        auto u_id = decoded.get_payload_claims().find("user_id");
        return std::string(u_id->second.as_string());

}

std::string Provider::generateToken(std::string user_id, std::string cert) {
        /* Read the priv and pub keys for the provider 
         * These will be used later for signing tokens. 
         */
        std::string rsa_priv = fileToString("../keys/provider.key");
        std::string rsa_crt = fileToString("../keys/provider.crt");
        std::string rsa_pub = getRSAPubFromCert(rsa_crt);
	
	auto token = jwt::create()
               	.set_issuer("Netflix")
               	.set_type("JWS")
               	.set_payload_claim("certu",jwt::claim(cert))
               	.set_payload_claim("provider_id", jwt::claim(getProviderId()))
               	.set_payload_claim("user_id", jwt::claim(user_id))
               	.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{2630000}) //One month expiry
               	.sign(jwt::algorithm::rs256(rsa_pub,rsa_priv,"",""));

	return token;
}

std::string Provider::getCertForUserId(std::string u_id) {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["userTable"];

                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
				document{} << 
				"_id" << bsoncxx::oid{bsoncxx::stdx::string_view{u_id}}
				<< finalize);

                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["uCert"];
                        std::string cert = result_element.get_utf8().value.to_string();
                        std::cout << "Successfully found user cert!" << std::endl;
                        return cert;
                }

                std::cerr << "[Provider.cc] Error, No User found with that ID" << '\n';
                return "0";
	} catch (std::exception &e) {
		std::cerr << "[Provider.cc] " << e.what() << '\n';
		std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getCertForUserId" << '\n';
		return "";
	}

}

int Provider::removeUserForUserId(std::string u_id) {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["userTable"];

                collection.delete_one(
				document{} << 
				"_id" << bsoncxx::oid{bsoncxx::stdx::string_view{u_id}}
				<< finalize);
		
		std::cout << "successfully removed user" << std::endl;

		return 1;
	} catch (std::exception &e) {
		std::cerr << "[Provider.cc] " << e.what() << '\n';
		std::cerr << "[Provider.cc] Error, deleting a user from the database failed in Provider::removeUserForUserId" << '\n';
		return 0;
	}
}

bool Provider::verifyRevocRequestSignature(std::string revoc_request, std::string request_signature, std::string stored_cert) {
	std::string pub_key = getRSAPubFromCert(stored_cert);
	return verifySig(pub_key, revoc_request, request_signature);
}

std::string Provider::getContentForContentName(std::string content_name) {
	std::ifstream f("content/" + content_name);
	if (!f.is_open()) {
		std::cerr << "Could not open file: " + content_name  << '\n';
		exit(0);
	}
	std::stringstream ss;
	ss << f.rdbuf();
	std::string fstr = ss.str();
	f.close();
	return fstr;
}

std::string Provider::fileToString(std::string filename) {
	std::ifstream f(filename);
	if(!f.is_open()) {
		std::cerr << "Could not open file: " + filename << '\n';
		exit(0);
	}
	std::stringstream ss;
	ss << f.rdbuf();
	std::string fstr = ss.str();
	f.close();
	return fstr;
}


int Provider::registerProvider(const std::string& pathForCert) {
	
	//Enable TLS Communications
	auto creds = buildClientCredentials(false);
	grpc::ChannelArguments channel_args = ChannelArguments();
	channel_args.SetSslTargetNameOverride("cloud.foo");
	std::unique_ptr<BackEndService::Stub> stub_(BackEndService::NewStub(grpc::CreateCustomChannel(
				"0.0.0.0:50055",creds,channel_args)));

	/* Read in the cert to send to register with */
	std::ifstream certFile(pathForCert);
	if(!certFile.is_open()) {
		std::cerr << "[!] Bad file path for Cert... quiting" << '\n';
		exit(0);
	}
	std::stringstream ss;
	ss << certFile.rdbuf();
	std::string certp = ss.str();
	certFile.close();

	/* Used for requesting from server*/
	CertP request;
	request.set_certp(certp);
	ProviderID reply;
	ClientContext context;

	/* call server code for registerProvider 
	 * If return status okay, check for valid returned providerID
	 */
	Status status = stub_->registerProvider(&context, request, &reply);
	if (status.ok()) {
		if(!reply.providerid().empty()) {
			std::cout << "[*] Succesfully registered access control with Edge!\n" << std::endl;
			std::cout << "given providerID: " << reply.providerid() << std::endl;
			this->m_providerID = reply.providerid();
			storeProviderId(reply.providerid());	
		} else {
			std::cerr << "[!] Cloud returned error code: " << '\n';
		}
	} else {
		std::cerr << "[Provider.cc] " << status.error_message() << std::endl;
		std::cerr << "[Provider.cc] " << status.error_details() << std::endl;
		std::cerr << "[Provider.cc] Error calling Cloud registerProvider!" << std::endl;
	}
	return 1;

} // end registerProvider


int Provider::notifyBlackListedToken(std::string uToken) {
	
	//Enable TLS Communications
        auto creds = buildClientCredentials(false);
        grpc::ChannelArguments channel_args = ChannelArguments();
        channel_args.SetSslTargetNameOverride("cloud.foo");
	std::unique_ptr<BackEndService::Stub> stub_(BackEndService::NewStub(grpc::CreateCustomChannel(
					"0.0.0.0:50055",creds,channel_args)));

	//Build request
	UserToken request;
	request.set_token(uToken);

	//Build necessary variables
	BlackListResponse reply;
	ClientContext context;

	//Call API
	Status status = stub_->registerBlackListedToken(&context, request, &reply);
	
	//Handle Response
	if (status.ok()) {
		std::cout << "[Provider.cc] All good on Provider Client side!" << std::endl;
	} else {
		std::cerr << "[Provider.cc] Error calling Cloud NotifyBlackListedToken" << '\n';
	}
	return 1;
}


int Provider::storeProviderId(std::string providerid) {
	try {
		mongocxx::uri uri("mongodb://127.0.0.1:27017");
		mongocxx::client client(uri);

		bsoncxx::builder::stream::document document{};

		auto collection = client["ProviderDB"]["edgeAccessControlData"];
		document << "myProviderId" << providerid;

		collection.insert_one(document.view());

		std::cout << "Successfully stored provider!" << std::endl;
		return 1;
	} catch (std::exception &e) {
		std::cerr << "[Provider.cc] Error in Provider.cc::storeProviderId()" << std::endl;
		std::cerr << "[Provider.cc] " << e.what() << std::endl;
		return 0;
	}
} // end StoreProviderId


std::string Provider::getProviderId() {
        try {
                static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["edgeAccessControlData"];

                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one({});

                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["myProviderId"];
                        std::string cert = result_element.get_utf8().value.to_string();
                        std::cout << "Successfully found provider id!" << std::endl;
                        return cert;
                }

                std::cerr << "[Provider.cc] Error, No Provider ID found" << '\n';
                return "0";
        } catch (std::exception &e) {
                std::cerr << "[Provider.cc] " << e.what() << '\n';
                std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getProviderId" << std::endl;
                return "";
        }

}

int Provider::storeUserData(const UserData *request, std::string token, std::string userId) {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		bsoncxx::builder::stream::document document{};

		auto collection = client["ProviderDB"]["userTable"];
		document << 
			"_id" << userId <<
		 	"username" << request->username() << 
			"password" << request->password() << 
			"optional_data" << request->optional_data() << 
			"uCert" << request->certu() <<
			"token" << token;

		//Insert entry
		auto returnValue = collection.insert_one(document.view());

		std::cout << "Successfully stored user!" << std::endl;
		return 1;
	} catch (std::exception &e) {
		std::cerr << "[Provider.cc] " << e.what() << std::endl;
		return 0;
	}
} // end storeUserData

std::shared_ptr<grpc::ChannelCredentials> Provider::buildClientCredentials(bool isSecure) {

        if (!isSecure)
                return std::shared_ptr<grpc::ChannelCredentials>(grpc::InsecureChannelCredentials());

        std::string key = fileToString("../keys/provider.key");
        std::string crt = fileToString("../keys/provider.crt");
        std::string ca = fileToString("../keys/ca.crt");
        grpc::SslCredentialsOptions tlsOpts;
        tlsOpts.pem_cert_chain = crt;
        tlsOpts.pem_private_key = key;
        tlsOpts.pem_root_certs = ca;
        std::shared_ptr<grpc::ChannelCredentials> creds = (grpc::SslCredentials(tlsOpts));
	return creds;
}// end buildClientCredentials


bool Provider::verifyUserCredentials(std::string username, std::string password) {
try {
                static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["userTable"];

                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
                                document{} <<
                                "username" << bsoncxx::oid{bsoncxx::stdx::string_view{username}}
                                << finalize);

                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["password"];
                        std::string stored_pass = result_element.get_utf8().value.to_string();
                        if (stored_pass.compare(password) == 0)
				return true;
			else
				return false;
                }

                std::cerr << "[Provider.cc] Error, No User found with that username" << '\n';
                return false;
        } catch (std::exception &e) {
                std::cerr << "[Provider.cc] " << e.what() << '\n';
                std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getUserIdForUsername" << '\n';
                return false;
        }

}

std::string Provider::getUserIdForUsername(std::string username) {
        try {
                static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["userTable"];

                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
                                document{} <<
                                "username" << username
                                << finalize);

                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["_id"];
                        std::string u_id = result_element.get_utf8().value.to_string();
                        std::cout << "Successfully found user id!" << std::endl;
                        return u_id;
                }

                std::cerr << "[Provider.cc] Error, No User found with that username" << '\n';
                return "0";
        } catch (std::exception &e) {
                std::cerr << "[Provider.cc] " << e.what() << '\n';
                std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getUserIdForUsername" << '\n';
                return "";
        }

}

int Provider::getAccessLevelForContentName(std::string name) {
        try {
                static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

		auto collection = client["ProviderDB"]["content"];


                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
                                document{} <<
                                "content_name" << name
                                << finalize);


                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["access_level"];
			int access_level = int(result_element.get_int32().value);
                        std::cout << "Successfully found access level!" << std::endl;
			std::cout << access_level << std::endl;
			return access_level;
                }

                std::cerr << "[Provider.cc] Error, No content found with that name" << '\n';
                return -1;
        } catch (std::exception &e) {
                std::cerr << "[Provider.cc] " << e.what() << '\n';
                std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getAccessLevelForContentName" << '\n';
                return -1;
        }
}

bool Provider::updateUserToken(std::string u_id, std::string new_token) {
        static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
        static const mongocxx::client client(uri);
        auto collection = client["ProviderDB"]["userTable"];

	auto result = collection.update_one(document{} << "_id" << bsoncxx::oid{bsoncxx::stdx::string_view{u_id}} << finalize, document{} << "$set" << open_document << "token" << new_token << close_document << finalize);	

	if(!result)
		return false;

	if (result.value().matched_count() == 1)
		return true;
	else
		return false;
}


bool Provider::updateCertForUserId(std::string u_id, std::string cert) {
        static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
        static const mongocxx::client client(uri);

        auto collection = client["ProviderDB"]["userTable"];

        auto result = collection.update_one(document{} << "_id" << bsoncxx::oid{bsoncxx::stdx::string_view{u_id}} << finalize, document{} << "$set" << open_document << "uCert" << cert << close_document << finalize); 
	
	if(!result)
		return false;

	if (result.value().matched_count() == 1)
		return true;
	else 
		return false;
}


int Provider::buildContentDatabase() {
	std::vector<std::string> file_names;
	std::string file_name;
	std::ifstream f ("./content/content_store.txt");
	if (f.is_open()) {
		while (! f.eof()) {
			getline(f, file_name);
			file_names.push_back(file_name);
		}
		f.close();
	} else {
		std::cerr << "[Provider.cc] Unable to open content_store.txt" << '\n';
		return 0;
	}

	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		auto collection = client["ProviderDB"]["content"];

		int num_files = file_names.size();
		std::string content_name;
		std::string content_data;
		int access_level;
		for (int i = 0; i<num_files; i++) {
			content_name = file_names.at(i);
			access_level = i % 3;
			std::cout << "Assigning " << content_name 
				<< " an access level of: " << access_level << std::endl;
			
			bsoncxx::builder::stream::document document{};
			document << 
			"content_name" << content_name <<
			"access_level" << access_level;
			
			//Insert entry
			auto returnValue = collection.insert_one(document.view());
		}
		std::cout << "Successfully stored content!" << std::endl;
		return 1;
	} catch(std::exception &e) {
		std::cout << "[Provider.cc] " << e.what() << std::endl;
		return 0;
	}

}

int Provider::buildKeyDatabase() {
	try {
		static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
		static const mongocxx::client client(uri);

		auto collection = client["ProviderDB"]["keys"];

		int access_level;
		for (int i = 0; i<3; i++) {
			access_level = i;
			std::cout << "Assigning " << access_level  
				<< " a key..." << std::endl;
			
			bsoncxx::builder::stream::document document{};
			document << 
			"access_level" << access_level <<
			"sym_key" << genRandString(32);
			
			//Insert entry
			auto returnValue = collection.insert_one(document.view());
		}
		std::cout << "Successfully stored keys!" << std::endl;
		return 1;
	} catch(std::exception &e) {
		std::cout << "[Provider.cc] " << e.what() << std::endl;
		return 0;
	}

}

std::string Provider::getAccessKeyForLevel(int level) {
        try {
                static const mongocxx::uri uri("mongodb://127.0.0.1:27017");
                static const mongocxx::client client(uri);

                auto collection = client["ProviderDB"]["keys"];

                bsoncxx::stdx::optional<bsoncxx::document::value> maybe_result = collection.find_one(
                                document{} <<
                                "access_level" << level
                                << finalize);

                if(maybe_result) {
                        bsoncxx::document::view result_view = maybe_result.value().view();
                        bsoncxx::document::element result_element = result_view["sym_key"];
                        std::string sym_key = result_element.get_utf8().value.to_string();
			std::cout << sym_key << std::endl;
                        std::cout << "Successfully found access key!" << std::endl;
                        return sym_key;
                }

                std::cerr << "[Provider.cc] Error, No key found with that access level" << '\n';
                return "";
        } catch (std::exception &e) {
                std::cerr << "[Provider.cc] " << e.what() << '\n';
                std::cerr << "[Provider.cc] Error, querying the database failed in Provider::getAccessKeyForLevel" << '\n';
                return "";
        }
}

std::string Provider::encryptDataForAccessLevel(std::string content_name, std::string data) {
	int access_level = getAccessLevelForContentName(content_name);
	std::string access_key = getAccessKeyForLevel(access_level);
	std::string enc_data = symEncAndEncode(data, access_key);
	return enc_data;
}

