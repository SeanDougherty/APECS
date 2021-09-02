#pragma once
#include <string>

#define CT_SIZE(PT_SIZE) ((PT_SIZE / 16 + 1) * 16) // calc the ciphertext size

enum CERT_FIELD {
	SUBJECT = 1,
	EXPIRE_TIME = 2,
	PUB_KEY = 3,
};


/* c++ friendly symetric encryption
 * base64 encodes the data for easier handling from the caller
 * defaults to iv of 16 '1''s
 */
std::string symEncAndEncode(std::string plaintext, std::string key);

/* c++ friendly symetric decryption
 * ciphertext must be in base64
 * defaults to iv of 16 '1''s
 */
std::string symDec(std::string ciphertext, std::string key);

/* AES CBC 256.
 */
int encrypt(unsigned char *pt, int pt_len, unsigned char *key,
					unsigned char *iv, unsigned char *ct);

// pt = plaintext; key -> 32bytes; iv -> 16bytes, ct -> ciphertext
// bitmasking a larger key sym_key (128bytes)

int decrypt(unsigned char *ct, int ct_len, unsigned char *key,
					unsigned char *iv, unsigned char *pt);


/* Generate a random c++ string of valid ascii characters to be used
 * as the symmetric key. This makes it easy to generate a random key, and send
 * it accross the wire without corruption.
 */
std::string genRandString(int num);

/* helper function to read in a file and return that file a string
 * Good for reading in PEM format files
 */
std::string read_as_string(std::string filename);

/* generate a random number of bytes, and return it as a string.
 */
std::string genBytes_string(int num);

/* generate random bytes, and return it as a char array, basically a wrapper
 * around openssl RAND_bytes()
 *
 */
char *genBytes(int num);

/* basic md5 hash of string, and returh the hex string of hash
 */
std::string md5hash(std::string data);

/* retrieve a specified field from a x509 cert in PEM format
 * field is specified by an enum represented at head of this file
 */
std::string getFieldFromCert(const std::string& cert_raw, int field);

/* return a PEM string of the pub key from cert_raw
 */
std::string getRSAPubFromCert(const std::string& cert_raw);

/* Check if the public key is the same as the pub key in the cert
 */
bool comparePubKeyWithCert(const std::string& pub_key, const std::string& cert_raw);

/* Extract the public key from a JWT, assuming there is one as one of the fields
 */
std::string getRSAPubFromToken(const std::string& user_token);

/* Encrypt a small piece of data ( symkey ) with and RSA public key
 */
unsigned char* encryptWithPubKey(const std::string& cert_raw, std::string data, int *length);

/* calls encryptWithPubKey, but transforms the binary data into a hex string
 * first before returning. The corresponding function to decrypt and decode
 * would be decryptSymKeyWithPubKey
 * !!! WARNING: these functions are only to be used to encrypt 32 byte data
 * 		and the symkey is not random bytes, but random string of alphanumeric
 * 		characters
 */
std::string encryptSymKeyWithPubKey(const std::string& pubkey, std::string data, int *length);

/* return a string version of the decrypted text. 
 * NEEDS: a hex encoded string to decode then call decryptWithPrivKey
 * !!! WARNING: these functions are only to be used to encrypt 32 byte data
 * 		and the symkey is not random bytes, but random string of alphanumeric
 * 		characters
 */
std::string decryptSymKeyWithPrivKey(const std::string& privkey, std::string ciphertext, int len);

/* decrypt the ciphertext using a passed in private key
 * No error handling for incorrect key pair
 */
char* decryptWithPrivKey(const std::string& privkey, const unsigned char* ciphertext, int len);

/* Given an x509 certificate, extract the public key and encrypt
 * a small piece of information with that public key
 */
std::string encryptWithCertPubKey(const std::string& cert_raw, std::string data, int *length);

/* Use openssl gen rand to generate a secure array of bits
 * return key as a string
 */
std::string genSymKey_string(int size);

/* return key as char*
 */
char* genSymKey(int size);

/* Verify the expiration date has not passed on an x509 cert in PEM format
 * return true if IS expired
 * return false if NOT expired
 */
bool isExpired(const std::string& cert_raw);


// token helpers

/* verify a signed token against a provided pubic key
 */
bool verifyToken(const std::string& token, const std::string& rsa_pub);

/* verify the cert in user_token matches that used in TLS_cert
 */
bool verifyTLS(const std::string& user_token, const std::string& TLS_cert);

/* return a base64 std::string encoded signature for easy handling
 * signs 'buff' with rsa_priv
 */
std::string sign(const std::string& rsa_priv, const std::string& buff);

/* Signs buff, with rsa_priv.
 * Signs bytes, NOT std::string, so needs the length of data to sign as well
 */
std::string sign_bytes(const std::string& rsa_priv, const unsigned char *buff,
		size_t buff_len);

/* verify a sig against buff using pub_key
 * sig is a base64 encoded std::string, so pass in as is.
 */
bool verifySig(const std::string& pub_key, const std::string& buff, 
		const std::string& b64_sig);

/* verify sig against buff using pub_key
 * sig is a base64 encoded std::string, so pass in as is.
 * buff is bytes, so must pass the length of data to it.
 */
bool verifySig_bytes(const std::string& pub_key, const unsigned char *buff,
		size_t buff_len, const std::string& b64_sig);

/* return a string for easy handling
 * Just tell it what to encode, and how long
 */
std::string b64_encode(const unsigned char *buffer, size_t length);

/* return binary data of what was encoded
 * pointer to length is used to relay to the caller how long the original data is
 */
unsigned char *b64_decode(const std::string& b64_string, size_t *length);


/**********************************************************************
 **********************************************************************
 * Internal API for crypto functions. Not meant for external use
 *********************************************************************
 ********************************************************************
 */

/* convert rsa key in pem format to rsa priv key
 * MUST BE PRIVATE KEY
 */
RSA *convertPEMtoRSA_priv(const char *rsa_priv);

/* convert rsa key in pem format to rsa pub key
 * MUST BE PUBLIC KEY
 */
RSA *convertPEMtoRSA_pub(const char *rsa_pub);


/* Internal function, using openssl EVP functions to do signing
 */
bool RSA_sign(RSA *rsa, const unsigned char *pt, size_t pt_len,
		unsigned char **ct, size_t *ct_len);

/* Internal function, using openssl EVP functions to do sig verification
 * Performs operation against a string.
 */
bool RSA_verify_sig(RSA* rsa, const std::string& b64_sig, const std::string& buff, 
		bool* is_auth);

/* Perform the RSA sig ver on bytes
 */
bool RSA_verify_sig_bytes(RSA* rsa, const std::string& b64_sig, const unsigned char *buff, 
		size_t buff_len, bool* is_auth);


size_t calc_b64_len(const char *input);

void die(std::string msg);



