#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <random>
#include <string>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

#include <jwt-cpp/jwt.h>

#include "crypto_wrap.hpp"


using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using ASN1_TIME_ptr = std::unique_ptr<ASN1_TIME, decltype(&ASN1_STRING_free)>;


std::string symEncAndEncode(std::string plaintext, std::string key)
{
	unsigned char iv[] = "1111111111111111";
	int enc_len = 0;
	int pt_len = plaintext.length();
	int ct_len = CT_SIZE(pt_len);
	int ct_len_ret = 0;
	unsigned char *ct = new unsigned char[ct_len+1];
	ct_len_ret = encrypt((unsigned char*)plaintext.c_str(), pt_len, 
						(unsigned char*)key.c_str(), iv, ct);
	if(ct_len_ret != ct_len) {
		std::cerr << "Error with encryption!" << std::endl;
	}
	ct[ct_len] = '\0';

	std::string b64_ciphertext = b64_encode(ct,ct_len);	
	// std::cout << b64_ciphertext << std::endl;
	delete(ct);
	return b64_ciphertext;
}

std::string symDec(std::string ciphertext, std::string key)
{
	unsigned char iv[] = "1111111111111111";
	unsigned char pt[ciphertext.length()];	
	size_t len;
	unsigned char *decoded_ct = b64_decode(ciphertext,&len);
	int pt_len = decrypt(decoded_ct,len,(unsigned char*)key.c_str(),iv,pt);
	pt[pt_len] = '\0';
	// std::cout << std::string(reinterpret_cast<char*>(pt)) << std::endl;
	return std::string(reinterpret_cast<char*>(pt));
}


int encrypt(unsigned char *pt, int pt_len, unsigned char *key,
					unsigned char *iv, unsigned char *ct)
{
	int ct_len = 0;
	int len = 0;
	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) die("crypto error1");
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) die("crypto error2");
	if (1 != EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)) die("crypto error3");
	ct_len = len;
	if (1 != EVP_EncryptFinal_ex(ctx, ct + len, &len)) die("crypto error4");
	ct_len += len;
	return ct_len;
}

int decrypt(unsigned char *ct, int ct_len, unsigned char *key,
					unsigned char *iv, unsigned char *pt)
{
	int pt_len = 0;
	int len = 0;
	EVP_CIPHER_CTX *ctx;
	if (!(ctx = EVP_CIPHER_CTX_new())) die("crypto error5");
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) die("crypto error6");
	if (1 != EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len)) die("crypto error7");
	pt_len = len;
	if (1 != EVP_DecryptFinal_ex(ctx, pt + len, &len)) {
	       	die("crypto error8");
	}
	pt_len += len;
	pt[pt_len] = '\0';
	return pt_len;
}


std::string genRandString(int num) {
	std::mt19937 generator{std::random_device{}()};	
	std::uniform_int_distribution<int> distribution{'0','9'};

	std::string genString(num, '\0');
	for(auto& dis : genString)
		dis = distribution(generator);

	return genString;
}

// issues may arrise turning a char* of binary data into a std::string
std::string genBytes_string(int num) {
	char *buff = (char*)malloc(num);
	RAND_bytes((unsigned char*)buff,num);
	std::string to_return = std::string(buff);
	free(buff);
	return to_return;
}


char *genBytes(int num) {
	char *buff = (char*)malloc(num);
	RAND_bytes((unsigned char*)buff,num);
	return buff;
}


std::string read_as_string(std::string filename) {
	std::ifstream inFile(filename);
	if(!inFile.is_open()) {
		std::cout << "Could not open file!!!" << std::endl;
		exit(0);
	}
	std::stringstream ss;
	ss << inFile.rdbuf();
	std::string file_as_string = ss.str();
	inFile.close();
	
	return file_as_string;
}


std::string md5hash(std::string data) {
	
	MD5_CTX md5context;
	MD5_Init(&md5context);
	MD5_Update(&md5context, data.c_str(), data.length());
	unsigned char res[MD5_DIGEST_LENGTH];
	MD5_Final(res, &md5context);

	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for(const auto &byte : res) {
		ss << std::setw(2) << (int)byte;
	}

	std::string fin = ss.str();
	return fin;
}

std::string getFieldFromCert(const std::string& cert_raw, int field) {
	OpenSSL_add_all_digests();

	BIO_ptr input(BIO_new(BIO_s_mem()), BIO_free);
	BIO_write(input.get(), cert_raw.c_str(), cert_raw.size());

	X509_ptr cert(PEM_read_bio_X509_AUX(input.get(),NULL,NULL,NULL), X509_free);
	BIO_ptr output_bio(BIO_new(BIO_s_mem()), BIO_free);

	// print whole cert
	//X509_print_ex(output_bio.get(), cert.get(),0,0);

	std::string cert_field;
	char buffer[4096];
	X509_NAME *subject;
	ASN1_TIME *expires;
	ASN1_TIME_ptr epoch(ASN1_TIME_new(), ASN1_STRING_free);
	ASN1_TIME_set_string(epoch.get(),"700101000000Z");
	int days, seconds;
	time_t expire_timestamp;
	// retrieve a specific field from the certificate
	switch(field) {
		case(SUBJECT):
			subject = X509_get_subject_name(cert.get());
			X509_NAME_print_ex(output_bio.get(),subject,0,0);
			memset(buffer,0,4096);
			BIO_read(output_bio.get(), buffer, 4096-1);
			cert_field = std::string(buffer);
			break;
		case(EXPIRE_TIME):
			expires = X509_get_notAfter(cert.get());
			ASN1_TIME_diff(&days, &seconds, epoch.get(), expires);
			expire_timestamp = (days * 24 * 60 * 60) + seconds;
			cert_field = (asctime(gmtime(&expire_timestamp)));
			break;
		default:
			std::cout << "[!] Need an option for the field of the certificate!" << std::endl;
			break;

	} // end switch

	ERR_free_strings();
	EVP_cleanup();

	return cert_field;

}


std::string encryptSymKeyWithPubKey(const std::string& pubkey, std::string data, int *len) {
	
	// encrypt data 
	unsigned char *ciphertext = encryptWithPubKey(pubkey, data, len);

	int data_len = data.length() * 8;

	// turn ciphertext into hex stringstream
	std::stringstream ss;
	for(int i = 0; i < data_len; i++) {
		ss << std::hex << (int)ciphertext[i] << " ";
	}

	// turn to stringstream -> string
	std::string s = ss.str();

	return s;
}

std::string decryptSymKeyWithPrivKey(const std::string& privkey, std::string ciphertext, int len) {
	// create a istringstream for the hex string
	std::istringstream hex_char_stream(ciphertext);
	std::vector<unsigned char> bytes;
	int c;
	
	// convert hex string to vector
	while(hex_char_stream >> std::hex >> c) {
		bytes.push_back(c);
	}

	// extract data from vector
	unsigned char *data = reinterpret_cast<unsigned char*>(bytes.data());

	// decrypt
	char *plaintext = decryptWithPrivKey(privkey, data, len);
	plaintext[bytes.size()] = '\0';

	// return the string version of plaintext
	return std::string(plaintext);

}


// just use the public key, forget the cert
unsigned char* encryptWithPubKey(const std::string& pubkey, std::string data, int *length) {

	RSA *rsa_pub_key = NULL;
	BIO *keybio = BIO_new_mem_buf((void*)pubkey.c_str(),-1);

	rsa_pub_key = PEM_read_bio_RSA_PUBKEY(keybio, &rsa_pub_key, NULL, NULL);

	unsigned char *ciphertext = (unsigned char*)malloc(RSA_size(rsa_pub_key));
	int len;
	if((len = RSA_public_encrypt(strlen(data.c_str()), (unsigned char*)data.c_str(),
					ciphertext,
					rsa_pub_key, RSA_PKCS1_OAEP_PADDING)) == -1) {

		std::cerr << "Error encrypting with RSA pub key" << std::endl;
		std::cerr << "Should quit here???" << std::endl;
		return 0;
	}
	*length = len;

	return ciphertext;
}

// up to user to free memory, but caller of function does NOT need to allocate
// memory for the decrypted data.
char* decryptWithPrivKey(const std::string& privkey, const unsigned char *ciphertext, int len) {
	RSA *rsa_priv_key = NULL;
	BIO *privkeybio = BIO_new_mem_buf((void*)privkey.c_str(),-1);

	rsa_priv_key = PEM_read_bio_RSAPrivateKey(privkeybio, &rsa_priv_key, NULL, NULL);
	char *plaintext = (char*)malloc(RSA_size(rsa_priv_key));
	if(RSA_private_decrypt(len, ciphertext, 
					(unsigned char*)plaintext, rsa_priv_key,
					RSA_PKCS1_OAEP_PADDING) == -1) {
		std::cerr << "Error decrypting with RSA priv key" << std::endl;
	}

	return plaintext;
}


// only works properly on 32 bytes of data
std::string encryptWithCertPubKey(const std::string& cert_raw, std::string data, int *length) {
	std::string rsa_pub = getRSAPubFromCert(cert_raw);
	std::string to_return = encryptSymKeyWithPubKey(rsa_pub,data,length);
	return to_return;
}


std::string getRSAPubFromCert(const std::string& cert_raw) {

	size_t cert_raw_len = strlen(cert_raw.c_str());
	BIO *certBio = BIO_new(BIO_s_mem());
	BIO_write(certBio, cert_raw.c_str(), cert_raw_len);
	
	X509 *cert = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
	if(!cert) {
		std::cerr << "unable to parse PEM cert in memory" << std::endl;
		return "";
	}

	/* Extract RSA Pub key from x509 type */
	EVP_PKEY *pubkey = X509_get_pubkey(cert);
	if(!pubkey) {fprintf(stderr,"error loading pub key from cert!\n");exit(0);}

	BIO *pkey_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(pkey_bio,pubkey);

	char *PEM_pubkey;
	long x = BIO_get_mem_data(pkey_bio,&PEM_pubkey);
	PEM_pubkey[x] = '\0';

	BIO_free(certBio);
	X509_free(cert);

	return std::string(PEM_pubkey);
}


std::string genSymKey_string(int size) {
	return "";
}


char* genSymKey(int size) {
	return 0;
}


bool isExpired(const std::string& cert_raw) {
	OpenSSL_add_all_digests();

	BIO_ptr input(BIO_new(BIO_s_mem()), BIO_free);
	BIO_write(input.get(), cert_raw.c_str(), cert_raw.size());

	X509_ptr cert(PEM_read_bio_X509_AUX(input.get(),NULL,NULL,NULL), X509_free);
	BIO_ptr output_bio(BIO_new(BIO_s_mem()), BIO_free);

	// print whole cert
	//X509_print_ex(output_bio.get(), cert.get(),0,0);

	int i = X509_cmp_current_time(X509_get_notAfter(cert.get()));
	if(i) {
		return false;
	}
	return true;

}


bool verifyToken(const std::string& token, const std::string& rsa_pub) {

	/* validate the user token */
	auto verifier = jwt::verify()
		.allow_algorithm(jwt::algorithm::rs256(rsa_pub,"","",""))
		.with_issuer("Netflix");


	auto decoded = jwt::decode(token);

	/* If token invalid, return to user */
	try {
		verifier.verify(decoded);
		return true;
	} catch(std::exception &e) {
		std::cerr << "[!] token INVALID" << std::endl;
		std::cerr << "error: " << e.what() << std::endl;
		return false;
	}
}


bool comparePubKeyWithCert(const std::string& pub_key, const std::string& cert_raw) {
	std::string pub_from_cert = getRSAPubFromCert(cert_raw);
	// string compare returns 0, if they are the same, so negate that
	// before returning.
	return (!pub_from_cert.compare(pub_key));
}


bool verifyTLS(const std::string& user_token, const std::string& TLS_cert) {
	/* get the user pub key from user_token */
	std::string pub_from_token = getRSAPubFromToken(user_token);
	/* compare pub key from token with the pub key from TLS_cert */
	return (comparePubKeyWithCert(pub_from_token,TLS_cert));
}


std::string getRSAPubFromToken(const std::string& user_token) {
	auto decoded = jwt::decode(user_token);

	// gets payload_claims as an unordered map that can be searched with find()
	auto x = decoded.get_payload_claims();
	// get the cert form token
	auto claim = x.find("certu");
	if(claim == x.end()) {
		std::cerr << "Error getting certu from user_token" << std::endl;
	}
	std::string pub_key = getRSAPubFromCert(claim->second.as_string());
	return (pub_key);
}


std::string b64_encode(const unsigned char *buffer, size_t length) {
	char *base64_text;
	BIO *bio = NULL, *b64 = NULL;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	// BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	base64_text = new char[bufferPtr->length + 1];
	memcpy(base64_text,bufferPtr->data,bufferPtr->length);
	std::string to_return = std::string(base64_text);

	return to_return;
}


unsigned char *b64_decode(const std::string& b64_string, size_t *length) {
	BIO *bio, *b64;

	int decode_len = calc_b64_len(b64_string.c_str());
	unsigned char *buffer = (unsigned char*)malloc(decode_len + 1);

	bio = BIO_new_mem_buf(b64_string.c_str(), -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64,bio);

	// BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*length = BIO_read(bio, buffer, b64_string.length());
	BIO_free_all(bio);
	buffer[decode_len] = '\0';
	return buffer;
}



std::string sign(const std::string& rsa_priv, const std::string& buff) {
	RSA *rsa = convertPEMtoRSA_priv(rsa_priv.c_str());
	unsigned char *sig;
	char *b64;
	size_t sig_len;
	RSA_sign(rsa,(unsigned char*)buff.c_str(),buff.length(),&sig,&sig_len);
	std::string b64_sig = b64_encode(sig,sig_len);
	return b64_sig;
}

std::string sign_bytes(const std::string& rsa_priv, const unsigned char *buff,
		size_t buff_len) {

	RSA *rsa = convertPEMtoRSA_priv(rsa_priv.c_str());
	unsigned char *sig;
	char *b64;
	size_t sig_len;
	RSA_sign(rsa,buff,buff_len,&sig,&sig_len);
	std::string b64_sig = b64_encode(sig,sig_len);
	return b64_sig;
}


bool verifySig(const std::string& pub_key, const std::string& buff,
		const std::string& b64_sig) {

	RSA* pub_rsa = convertPEMtoRSA_pub(pub_key.c_str());
	size_t sig_len;
	bool is_auth;

	bool res = RSA_verify_sig(pub_rsa, b64_sig, buff, &is_auth);
	return (res & is_auth);
}

bool verifySig_bytes(const std::string& pub_key, const unsigned char *buff,
		size_t buff_len, const std::string& b64_sig) {

	RSA* pub_rsa = convertPEMtoRSA_pub(pub_key.c_str());
	size_t sig_len;
	bool is_auth;
	bool res = RSA_verify_sig_bytes(pub_rsa, b64_sig, buff, buff_len, &is_auth);
	return (res & is_auth);
}


/**********************************************************************
 * Internal API for crypto functions. Not meant for external use
 *********************************************************************/

bool RSA_sign(RSA *rsa, const unsigned char *pt, size_t pt_len,
	unsigned char **ct, size_t *ct_len) {

	EVP_MD_CTX *RSA_sign_CTX = EVP_MD_CTX_create();
	EVP_PKEY *priv_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(priv_key, rsa);

	if(EVP_DigestSignInit(RSA_sign_CTX, NULL, EVP_sha256(),NULL,priv_key)<=0)
		return false;

	if(EVP_DigestSignUpdate(RSA_sign_CTX,pt,pt_len)<=0)
		return false;

	if(EVP_DigestSignFinal(RSA_sign_CTX,NULL,ct_len)<=0)
		return false;

	*ct = (unsigned char*)malloc(*ct_len);
	if(EVP_DigestSignFinal(RSA_sign_CTX, *ct,ct_len)<=0)
		return false;

	EVP_MD_CTX_free(RSA_sign_CTX);
	return true;
}


bool RSA_verify_sig(RSA* rsa, const std::string& b64_sig, const std::string& buff, 
		bool* is_auth) {

	size_t sig_len = 0;
	unsigned char *sig = b64_decode(b64_sig,&sig_len);
	*is_auth = false;
	EVP_PKEY* pub_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pub_key,rsa);
	EVP_MD_CTX* RSA_verify_CTX = EVP_MD_CTX_create();
	if(EVP_DigestVerifyInit(RSA_verify_CTX, NULL, EVP_sha256(),NULL,pub_key)<=0) 
		return false;
	if(EVP_DigestVerifyUpdate(RSA_verify_CTX,buff.c_str(),buff.length())<=0)
		return false;
	int auth_status = EVP_DigestVerifyFinal(RSA_verify_CTX,sig,sig_len);
	if(auth_status == 1) {
		*is_auth = true;
		EVP_MD_CTX_free(RSA_verify_CTX);
		return true;
	} else if(auth_status == 0) {
		*is_auth = false;
		EVP_MD_CTX_free(RSA_verify_CTX);
		return true;
	} else {
		*is_auth = false;
		EVP_MD_CTX_free(RSA_verify_CTX);
		return false;
	}
}


bool RSA_verify_sig_bytes(RSA* rsa, const std::string& b64_sig, const unsigned char *buff, 
		size_t buff_len, bool* is_auth) {

	size_t sig_len = 0;
	unsigned char *sig = b64_decode(b64_sig,&sig_len);
	*is_auth = false;
	EVP_PKEY* pub_key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pub_key,rsa);
	EVP_MD_CTX* RSA_verify_CTX = EVP_MD_CTX_create();

	if(EVP_DigestVerifyInit(RSA_verify_CTX, NULL, EVP_sha256(),NULL,pub_key)<=0) 
		return false;

	if(EVP_DigestVerifyUpdate(RSA_verify_CTX,buff,buff_len)<=0)
		return false;

	int auth_status = EVP_DigestVerifyFinal(RSA_verify_CTX,sig,sig_len);
	if(auth_status == 1) {
		*is_auth = true;
		EVP_MD_CTX_free(RSA_verify_CTX);
		return true;
	} else if(auth_status == 0) {
		*is_auth = false;
		EVP_MD_CTX_free(RSA_verify_CTX);
		return true;
	} else {
		*is_auth = false;
		EVP_MD_CTX_free(RSA_verify_CTX);
		return false;
	}
}


RSA *convertPEMtoRSA_priv(const char *rsa_priv) {
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf((void*)rsa_priv, -1);
	if(keybio == NULL) {fprintf(stderr,"[!] Error with priv key bio!\n");exit(0);}

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	return rsa;
}

RSA *convertPEMtoRSA_pub(const char *rsa_pub) {
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf((void*)rsa_pub, -1);
	if(keybio == NULL) {fprintf(stderr,"[!] Error with pub key bio!\n");exit(0);}

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	return rsa;
}

size_t
calc_b64_len(const char* base64_input)
{
	size_t len = strlen(base64_input), padding = 0;

	if(base64_input[len-1] == '=' && base64_input[len-2] == '=')
		padding = 2;
	else if(base64_input[len-1] == '=')
		padding = 1;
	return(len*3)/4 - padding;
}

void die(std::string msg)
{
	std::cerr << msg << std::endl;
	exit(1);
}





