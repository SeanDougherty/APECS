
#include "User.h"
#include "../Lib/crypto_wrap.hpp"

/************************************************
 * 		User Client Methods		*
 ************************************************/

/*
 * Register user credentials with the provider
 */
int User::registerUser() {

	//Enable TLS Communications
	auto creds = buildClientCredentials(false);
	grpc::ChannelArguments channel_args = ChannelArguments();
	channel_args.SetSslTargetNameOverride("provider.foo");
	std::unique_ptr<ProviderService::Stub> stub_(ProviderService::NewStub(grpc::CreateCustomChannel("0.0.0.0:50077",creds,channel_args)));
	
	//Prepare values for request
	std::string crt = fileToString("../keys/user.crt");

	this->m_username = "user";
	this->m_password = "pass";

	//Build request
	UserData request;
	request.set_username(this->m_username);
	request.set_password(this->m_password);
	request.set_access_level(2);
	request.set_optional_data("NA");
	request.set_certu(crt);

	//Build necessary variables
	UserTokenAndSymKey reply;
	ClientContext context;

	//Call API
	Status status = stub_->registerUser(&context,request,&reply);

	//Handle Response
	if (status.ok()) {
		std::cout << "User successfully registered" << std::endl;
		std::string priv_key = fileToString("../../keys/www.example.com.key");
		this->m_symkey = decryptSymKeyWithPrivKey(priv_key, reply.symkey(), reply.symkey_length());
		this->m_user_token = reply.token();
		std::cout << "decrypted key: " << this->m_symkey << std::endl;
		return 1;
	} else {
		std::cout << "Error when calling User::registerUser" << std::endl;
		return 0;
	}

} // end registerUser

/*
 * Request data through edge server
 */
int User::requestData(std::string content_name) {

    if (this->m_user_token == ""){
        std::cout << "no user token stored, please register as a user before requesting data" << std::endl;
        return 0;
    }

    int test_ct = 4;

		int elapsed_times [test_ct];


    for (int i=0; i < test_ct; i++) {
			auto start = std::chrono::high_resolution_clock::now();

			//Enable TLS Communications
			auto creds = buildClientCredentials(false);
			grpc::ChannelArguments channel_args = ChannelArguments();
			channel_args.SetSslTargetNameOverride("edgeserver.foo");
			std::unique_ptr<EdgeServerService::Stub> stub_(EdgeServerService::NewStub(
									grpc::CreateCustomChannel("0.0.0.0:50033",creds,channel_args)));

			
			std::string service_request = buildServiceRequest(content_name);
			std::string signature = signServiceRequest(service_request);

			
			//Build request
			UserDataRequest request;
			request.set_user_token(this->m_user_token);
			request.set_content_name(content_name);
			request.set_signature(signature);

			//Build necessary variables
			DataPayload reply;
			ClientContext context;

			//Call API
			Status status = stub_->requestData(&context, request, &reply);


			//Handle response
			if (status.ok()) {
					handleDataReceived(&reply);
			} else {
					std::cout << "Error in User::requestData" << std::endl;
					std::cout << "Message Recieved: " << reply.msg() << std::endl;
			}
			auto stop = std::chrono::high_resolution_clock::now();
			auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop-start);
			int microseconds = int(duration.count());
			elapsed_times[i] = microseconds;
    }

		std::string alls = "";
    for(int j=0; j < test_ct; j++) {
        if (j < test_ct-1) {
					alls = alls + std::to_string(elapsed_times[j]) + ", ";
        } else {
					alls = alls + std::to_string(elapsed_times[j]);
        }
    }
    stringToFile(alls, "data_full_runtimes.csv");

    return 1;
} // end requestData



int User::requestService() {

	if (this->m_user_token == ""){
		std::cout << "no user token stored, please register as a user before requesting service" << std::endl;
		return 0;
	}

	std::string payload = fileToString("./decrypted_text.txt");
	//Load in cryptographic values
	py::module_ mabe = py::module_::import("mabe");	//Enable TLS Communications
	struct SetupVars* setupvars = c_setup();	

	// SetupVars
	std::string Y (reinterpret_cast<char*>(setupvars-> Y ), setupvars->Y_len);
	std::string g2 (reinterpret_cast<char*>(setupvars-> g2 ), setupvars->g2_len);
	std::string T_1a1 (reinterpret_cast<char*>(setupvars-> T_1a1 ), setupvars->T_1a1_len);
	std::string T_1a2 (reinterpret_cast<char*>(setupvars-> T_1a2 ), setupvars->T_1a2_len);
	std::string T_2a2 (reinterpret_cast<char*>(setupvars-> T_2a2 ), setupvars->T_2a2_len);
	std::string T_2a3 (reinterpret_cast<char*>(setupvars-> T_2a3 ), setupvars->T_2a3_len);
	std::string T_3a1 (reinterpret_cast<char*>(setupvars-> T_3a1 ), setupvars->T_3a1_len);
	std::string T_3a3 (reinterpret_cast<char*>(setupvars-> T_3a3 ), setupvars->T_3a3_len);
	std::string S_1_1_u1 (reinterpret_cast<char*>(setupvars-> S_1_1_u1 ), setupvars->S_1_1_u1_len);
	std::string g1 (reinterpret_cast<char*>(setupvars-> g1 ), setupvars->g1_len);
	std::string coeff_auth1_u1_0 (reinterpret_cast<char*>(setupvars-> coeff_auth1_u1_0 ), setupvars->coeff_auth1_u1_0_len);
	std::string coeff_auth1_u1_1 (reinterpret_cast<char*>(setupvars-> coeff_auth1_u1_1 ), setupvars->coeff_auth1_u1_1_len);
	std::string S_1_2_u1 (reinterpret_cast<char*>(setupvars-> S_1_2_u1 ), setupvars->S_1_2_u1_len);
	std::string S_2_2_u1 (reinterpret_cast<char*>(setupvars-> S_2_2_u1 ), setupvars->S_2_2_u1_len);
	std::string coeff_auth2_u1_0 (reinterpret_cast<char*>(setupvars-> coeff_auth2_u1_0 ), setupvars->coeff_auth2_u1_0_len);
	std::string coeff_auth2_u1_1 (reinterpret_cast<char*>(setupvars-> coeff_auth2_u1_1 ), setupvars->coeff_auth2_u1_1_len);
	std::string S_2_3_u1 (reinterpret_cast<char*>(setupvars-> S_2_3_u1 ), setupvars->S_2_3_u1_len);
	std::string coeff_auth3_u1_0 (reinterpret_cast<char*>(setupvars-> coeff_auth3_u1_0 ), setupvars->coeff_auth3_u1_0_len);
	std::string coeff_auth3_u1_1 (reinterpret_cast<char*>(setupvars-> coeff_auth3_u1_1 ), setupvars->coeff_auth3_u1_1_len);
	std::string S_3_1_u1 (reinterpret_cast<char*>(setupvars-> S_3_1_u1 ), setupvars->S_3_1_u1_len);
	std::string S_3_3_u1 (reinterpret_cast<char*>(setupvars-> S_3_3_u1 ), setupvars->S_3_3_u1_len);
	std::string D_u1 (reinterpret_cast<char*>(setupvars-> D_u1 ), setupvars->D_u1_len);
	std::string temp_1_GT (reinterpret_cast<char*>(setupvars-> temp_1_GT ), setupvars->temp_1_GT_len);
	std::string temp_1_Zr (reinterpret_cast<char*>(setupvars-> temp_1_Zr ), setupvars->temp_1_Zr_len);
	std::string temp_2_Zr (reinterpret_cast<char*>(setupvars-> temp_2_Zr ), setupvars->temp_2_Zr_len);
	std::string e_g1g2 (reinterpret_cast<char*>(setupvars-> e_g1g2 ), setupvars->e_g1g2_len);


	int test_ct = 10;

	int elapsed_times [test_ct];
	int elapsed_enc_times [test_ct];
	int elapsed_sym_times [test_ct];
	int elapsed_sign_times [test_ct];
	for (int i=0; i < test_ct; i++) {
		auto start = std::chrono::high_resolution_clock::now();

	
		auto creds = buildClientCredentials(false);
		grpc::ChannelArguments channel_args = ChannelArguments();
		channel_args.SetSslTargetNameOverride("edgeserver.foo");
		std::unique_ptr<EdgeServerService::Stub> stub_(EdgeServerService::NewStub(grpc::CreateCustomChannel("0.0.0.0:50033", creds, channel_args)));

		std::string service_data;
		std::string service_request;
		std::string signature;
		std::string setup_json;
		std::string enc_json;
		auto enc_start = std::chrono::high_resolution_clock::now();
		struct EncryptVars* encryptvars = c_encrypt(setupvars);
		auto enc_stop = std::chrono::high_resolution_clock::now();
		// EncryptVars
		std::string E_0 (reinterpret_cast<const char*>(encryptvars-> E_0 ), encryptvars->E_0_len);
		std::string E_1 (reinterpret_cast<const char*>(encryptvars-> E_1 ), encryptvars->E_1_len);
		std::string C_1_1 (reinterpret_cast<const char*>(encryptvars-> C_1_1 ), encryptvars->C_1_1_len);
		
		std::string C_1_2 (reinterpret_cast<const char*>(encryptvars-> C_1_2 ), encryptvars->C_1_2_len);
		std::string C_2_2 (reinterpret_cast<const char*>(encryptvars-> C_2_2 ), encryptvars->C_2_2_len);
		std::string C_2_3 (reinterpret_cast<const char*>(encryptvars-> C_2_3 ), encryptvars->C_2_3_len);
		std::string C_3_1 (reinterpret_cast<const char*>(encryptvars-> C_3_1 ), encryptvars->C_3_1_len);
		std::string C_3_3 (reinterpret_cast<const char*>(encryptvars-> C_3_3 ), encryptvars->C_3_3_len);
		std::string msg (reinterpret_cast<const char*>(encryptvars-> msg ), encryptvars->msg_len);
		std::string s (reinterpret_cast<const char*>(encryptvars-> s ), encryptvars->s_len);
		std::string L1_0_Auth1 (reinterpret_cast<const char*>(encryptvars-> L1_0_Auth1 ), encryptvars->L1_0_Auth1_len);
		std::string L2_0_Auth1 (reinterpret_cast<const char*>(encryptvars-> L2_0_Auth1 ), encryptvars->L2_0_Auth1_len);
		std::string L2_0_Auth2 (reinterpret_cast<const char*>(encryptvars-> L2_0_Auth2 ), encryptvars->L2_0_Auth2_len);
		std::string L3_0_Auth2 (reinterpret_cast<const char*>(encryptvars-> L3_0_Auth2 ), encryptvars->L3_0_Auth2_len);
		std::string L1_0_Auth3 (reinterpret_cast<const char*>(encryptvars-> L1_0_Auth3 ), encryptvars->L1_0_Auth3_len);
		std::string L3_0_Auth3 (reinterpret_cast<const char*>(encryptvars-> L3_0_Auth3 ), encryptvars->L3_0_Auth3_len);

		c_free_encrypt(encryptvars);
		auto sym_start = std::chrono::high_resolution_clock::now();	
		py::object payload_data = mabe.attr("encryptPayload2")("12345678901234567890", payload);
		auto sym_stop = std::chrono::high_resolution_clock::now();
		service_data = payload_data.cast<std::string>();
		auto sign_start = std::chrono::high_resolution_clock::now();
		service_request = buildServiceRequest(service_data);
		signature = signServiceRequest(service_request);
		auto sign_stop = std::chrono::high_resolution_clock::now();

		//Build request
		UserServiceRequest request;
		request.set_user_token(this->m_user_token);
		request.set_service_data(service_data);
		request.set_abe_setup_json(setup_json);
		request.set_abe_enc_json(enc_json);
		request.set_signature(signature);
		request.set_y(Y);
		request.set_g2( g2 );
		request.set_t_1a1( T_1a1 );
		request.set_t_1a2( T_1a2 );
		request.set_t_2a2( T_2a2 );
		request.set_t_2a3( T_2a3 );
		request.set_t_3a1( T_3a1 );
		request.set_t_3a3( T_3a3 ); 
		request.set_s_1_1_u1( S_1_1_u1 );
		request.set_g1( g1 );
		request.set_coeff_auth1_u1_0( coeff_auth1_u1_0 );
		request.set_coeff_auth1_u1_1( coeff_auth1_u1_1 );
		request.set_s_1_2_u1( S_1_2_u1 );
		request.set_s_2_2_u1( S_2_2_u1 );
		request.set_coeff_auth2_u1_0( coeff_auth2_u1_0 ); 
		request.set_coeff_auth2_u1_1( coeff_auth2_u1_1 );
		request.set_s_2_3_u1( S_2_3_u1 );
		request.set_coeff_auth3_u1_0( coeff_auth3_u1_0 );
		request.set_coeff_auth3_u1_1( coeff_auth3_u1_1 );
		request.set_s_3_1_u1( S_3_1_u1 );
		request.set_s_3_3_u1( S_3_3_u1 );
		request.set_d_u1( D_u1 );
		request.set_temp_1_gt( temp_1_GT );
		request.set_temp_1_zr( temp_1_Zr );
		request.set_temp_2_zr( temp_2_Zr );
		request.set_e_g1g2( e_g1g2 );

		// encryptVars
		request.set_e_0( E_0 );
		request.set_e_1( E_1 );
		request.set_c_1_1( C_1_1 );
		request.set_c_1_2( C_1_2 );
		request.set_c_2_2( C_2_2 );
		request.set_c_2_3( C_2_3 );
		request.set_c_3_1( C_3_1 );
		request.set_c_3_3( C_3_3 );
		request.set_msg( msg );
		request.set_s( s );
		request.set_l1_0_auth1( L1_0_Auth1 );
		request.set_l2_0_auth1( L2_0_Auth1 );
		request.set_l2_0_auth2( L2_0_Auth2 );
		request.set_l3_0_auth2( L3_0_Auth2 );
		request.set_l1_0_auth3( L1_0_Auth3 );
		request.set_l3_0_auth3( L3_0_Auth3 );


		ServiceResponse reply;
		ClientContext context;
	
		//Call API
		Status status = stub_->requestService(&context, request, &reply);
	
	
		//Handle response
		if (status.ok()) {
//			std::cout << "Message Recieved: " << reply.result() << std::endl;
		} else {
			std::cout << "Error in User::requestService" << std::endl;
			std::cout << status.error_message() << std::endl;
			std::cout << "Message Recieved: " << reply.result() << std::endl;
			std::cout << std::endl;
		}
		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop-start);
		auto enc_duration = std::chrono::duration_cast<std::chrono::microseconds>(enc_stop-enc_start);
		auto sym_duration = std::chrono::duration_cast<std::chrono::microseconds>(sym_stop-sym_start);
		auto sign_duration = std::chrono::duration_cast<std::chrono::microseconds>(sign_stop-sign_start);
		int microseconds = int(duration.count());
		int enc_microseconds = int(enc_duration.count());
		int sym_microseconds = int(sym_duration.count());
		int sign_microseconds = int(sign_duration.count());
		elapsed_times[i] = microseconds;
		elapsed_enc_times[i] = enc_microseconds;
		elapsed_sym_times[i] = sym_microseconds;
		elapsed_sign_times[i] = sign_microseconds;
	}

	std::string encs = "";
	std::string alls = "";
	std::string syms = "";
	std::string signs = "";
	for(int j=0; j < test_ct; j++) {
		if (j < test_ct-1) {
			encs = encs + std::to_string(elapsed_enc_times[j]) + ", ";
			alls = alls + std::to_string(elapsed_times[j]) + ", ";
			syms = syms + std::to_string(elapsed_sym_times[j]) +", ";
			signs = signs + std::to_string(elapsed_sign_times[j]) +", ";
		} else {
			encs = encs + std::to_string(elapsed_enc_times[j]);
			alls = alls + std::to_string(elapsed_times[j]);
			syms = syms + std::to_string(elapsed_sym_times[j]);
			signs = signs + std::to_string(elapsed_sign_times[j]);
		}
	}
	stringToFile(encs, "encrypt_runtimes.csv");
	stringToFile(alls, "full_runtimes.csv");
	stringToFile(syms, "sym_runtimes.csv");
	stringToFile(signs, "sign_runtimes.csv");
	return 1;

} // end requestService

int User::systemCallEncryptData(){
	std::string system_call_string = "python3 improvedmultiabe.py e";
	const char *command = system_call_string.c_str();
	system(command);
} // end systemCallEncryptData

int User::stringToFile(std::string data, std::string filename){
	std::ofstream f(filename);
	f << data;
	f.close();
	return 0;
} // end stringToFile

/*
 * Request Revocation of services from provider
 */
int User::requestRevocation() {
	
	//Enable TLS Communications
	auto creds = buildClientCredentials(false);
	grpc::ChannelArguments channel_args = ChannelArguments();
	channel_args.SetSslTargetNameOverride("provider.foo");
	std::unique_ptr<ProviderService::Stub> stub_(ProviderService::NewStub(
	grpc::CreateCustomChannel("0.0.0.0:50077",creds,channel_args)));

	//Build revocation request
	std::string revocRequest = buildRevocRequest();
	std::string signature = signRevocRequest(revocRequest);

	//Build request
	RevocRequest request;	
	request.set_revoc_request(revocRequest);
	request.set_request_signature(signature);
	request.set_user_token(this->m_user_token);

	//Build necessary variables
	RevocResponse reply;
	ClientContext context;

	//Call API
	Status status = stub_->requestRevocation(&context,request,&reply);
	
	//Handle response
	if (status.ok()) {
		std::cout << "status okay from provider" << std::endl;
		std::cout << "[*] response code: " << reply.response_code() << std::endl;
		std::cout << "msg: " << reply.msg() << std::endl;
		return 1;
	} else {
		std::cout << status.error_message() << std::endl;
		std::cout << status.error_details() << std::endl;
		std::cout << "Error communication w/ Provider in User::requestRevocation" << std::endl;
		return 0;
	}
} // end requestRevocation


int User::renewToken(){
 	//Enable TLS Communications
	auto creds = buildClientCredentials(false);
	grpc::ChannelArguments channel_args = ChannelArguments();
	channel_args.SetSslTargetNameOverride("provider.foo");

	std::unique_ptr<ProviderService::Stub> stub_(ProviderService::NewStub(
													grpc::CreateCustomChannel("192.122.236.103:50077",creds,channel_args)));

	//Build request
	UserCredentials request;
	request.set_username(this->m_username);
	request.set_password(this->m_password);

	//Build necessary variables
	NewToken reply;
	ClientContext context;

	//Call API
	Status status = stub_->renewToken(&context,request,&reply);

	//Handle response
	if (status.ok()) {
		this->m_user_token = reply.user_token();
		std::cout << "status okay from provider" << std::endl;
		return 1;
	} else {
		std::cout << "Error communication w/ Provider in User::renewToken" << std::endl;
		return 0;
	}
}


/************************************************
 *              User Helper Methods             *
 ************************************************/

int User::handleDataReceived(DataPayload* reply) {
	std::string data = reply->data();
	int access_level = reply->access_level();
	// retrieve sym key for access level
	std::vector<std::string> sym_keys;
	std::string sym_key;
	std::string sym_key_dec;
	sym_keys = split(this->m_symkey, " ");
	try {
		sym_key_dec = sym_keys[access_level];
	} catch (std::exception &e) {
		std::cout << "error trying to handle sym_keys" << std::endl;
		return -1;
	}

	std::string plaintext = symDec(data, sym_key_dec);

	return 0;
}


std::string User::buildServiceRequest(std::string service_data) {
	auto decoded = jwt::decode(this->m_user_token);
	auto claims = decoded.get_payload_claims();
	auto u_id = claims.find("user_id");
	std::string token_piece = std::string(u_id->second.as_string());
	std::string service_request = service_data + "|" + token_piece;
	return service_request;
}

std::string User::signServiceRequest(std::string service_request) {
	std::string key = fileToString("../keys/user.key");
	std::string signature = sign(key, service_request);
	return signature;	
}


std::string User::buildRevocRequest() {
	auto decoded = jwt::decode(this->m_user_token);
	auto claims = decoded.get_payload_claims();
	auto u_id = claims.find("user_id");
	std::string request = std::string(u_id->second.as_string());
	return request;
}// end buildRevocRequest


/*
 * 
 */
std::string User::signRevocRequest(std::string request) {
	std::string key = fileToString("../keys/user.key");
	std::string signature = sign(key, request);
	return signature;
}// end signRevocRequest

/*
 * TLS helper function
 */
std::shared_ptr<grpc::ChannelCredentials> User::buildClientCredentials(bool isSecure) {
	
	// Return basic credentials if TLS is not needed
	if (!isSecure)
		return std::shared_ptr<grpc::ChannelCredentials>(grpc::InsecureChannelCredentials());

	//Read in files for credentials
	std::string key = fileToString("../keys/user.key");
	std::string crt = fileToString("../keys/user.crt");
	std::string ca = fileToString("../keys/ca.crt");
	
	//Build the option object
	grpc::SslCredentialsOptions tlsOpts;
	tlsOpts.pem_cert_chain = crt;
	tlsOpts.pem_private_key = key;
	tlsOpts.pem_root_certs = ca;
	
	return std::shared_ptr<grpc::ChannelCredentials>(grpc::SslCredentials(tlsOpts));
}// end buildClientCredentials


std::vector<std::string> User::split(std::string str,std::string sep){
	char* cstr=const_cast<char*>(str.c_str());
	char* current;
	std::vector<std::string> arr;
	current=strtok(cstr,sep.c_str());
	while(current!=NULL){
		arr.push_back(current);
		current=strtok(NULL,sep.c_str());
	}
	return arr;
}

void User::setUserCert() {
	this->user_cert = fileToString("../keys/user.crt");
}

/*
 * 
 */
std::string User::fileToString(std::string filename) {
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
