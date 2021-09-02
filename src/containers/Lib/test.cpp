// resource used to learn gtest
//https://developer.ibm.com/articles/au-googletestingframework/
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <cstring>
#include <openssl/rand.h>
#include <vector>
#include <jwt-cpp/jwt.h>

#include "crypto_wrap.hpp"

#include "gtest/gtest.h"

class CryptoTestFixture: public ::testing::Test {
	public:
	CryptoTestFixture(){}
	void SetUp(){}
	void TearDown(){}
	~CryptoTestFixture(){}

	std::string pubkey =  read_as_string("../../keys/www.example.com.pubkey.pem");
	std::string privkey = read_as_string("../../keys/www.example.com.key");
	std::string certPEM = read_as_string("../../keys/www.example.com.cert");
	std::string badpub = read_as_string("../../keys/rsa_pub.pem");
	unsigned char *key = (unsigned char*)"11345611245111111118898111878111";
	unsigned char *iv = (unsigned char*)"1111111111111111";
	std::string key_string = "11345611245111111118898111878111";
};

TEST_F(CryptoTestFixture, VerifyToken)
{
	std::string rsa_pub = getRSAPubFromCert(certPEM);
	
	auto token = jwt::create()
               	.set_issuer("Netflix")
               	.set_type("JWS")
               	.set_payload_claim("certu",jwt::claim(certPEM))
               	.set_payload_claim("provider_id", jwt::claim(std::string("111")))
               	.set_payload_claim("user_id", jwt::claim(std::string("111")))
               	.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{2630000}) //One month expiry
               	.sign(jwt::algorithm::rs256(rsa_pub,privkey,"",""));


	bool status = verifyToken(token, pubkey);
	ASSERT_TRUE(status);

}

// test c++ sym enc
TEST_F(CryptoTestFixture, CppSymEncTest)
{
	std::string plaintext = "hello world!";
	std::string ct = symEncAndEncode(plaintext,key_string);
	std::string pt = symDec(ct,key_string);
	ASSERT_EQ(plaintext,pt);
}

TEST_F(CryptoTestFixture, aesTest)
{
	std::string test = "hello world";
	unsigned char *ct = (unsigned char*)malloc(CT_SIZE(test.length()));
	unsigned char *pt = (unsigned char*)malloc(test.length()+1);
	int len = encrypt((unsigned char*)test.c_str(),test.length(),key,iv,ct);
	len = decrypt(ct,len,key,iv,pt);
	std::string final_val = std::string(reinterpret_cast<char*>(pt));
	ASSERT_EQ(final_val,test);
}

// token pub key in cert in jwt against the known pubkey
TEST_F(CryptoTestFixture, CompareJWTCertWithPubCert)
{
	auto token = jwt::create()
		.set_issuer("auto0")
		.set_type("JWS")
		.set_payload_claim("certu",jwt::claim(std::string(certPEM)))
		.sign(jwt::algorithm::hs256{"secret"});

	auto decoded = jwt::decode(token);

	auto x = decoded.get_payload_claims();
	auto claim = x.find("certu");
	std::string c = std::string(claim->second.as_string());

	ASSERT_TRUE(comparePubKeyWithCert(pubkey,c));
}

TEST_F(CryptoTestFixture, TestPubFromCert)
{
	std::string p = getRSAPubFromCert(certPEM);
	ASSERT_TRUE(comparePubKeyWithCert(p,certPEM));
	ASSERT_FALSE(comparePubKeyWithCert(badpub,certPEM));
}


int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();

	/*
	unsigned char *key = (unsigned char *)"11345611245111111118898111878111";
	unsigned char *iv = (unsigned char *)"1111643645117111";

	std::string test = "hello world";
	unsigned char *ct = (unsigned char*)malloc(CT_SIZE(test.length()));
	unsigned char *pt = (unsigned char*)malloc(test.length()+1);
	int len = encrypt((unsigned char*)test.c_str(),test.length(),key,iv,ct);
	len = decrypt(ct,len,key,iv,pt);
	std::cout << std::string(reinterpret_cast<char*>(pt)) << std::endl;
	*/


	/*
	int len = 0;
	std::string symkey = genRandString(32);
	std::cout << symkey << std::endl;
	std::string ct = encryptWithCertPubKey(certPEM,symkey,&len);

	std::string plaintext = decryptSymKeyWithPrivKey(privkey, ct, len);
	std::cout << plaintext << std::endl;
	*/




	/*
	std::string test = "hello world";
	std::string ttest = "hello oorld";
	//std::cout << test << std::endl;


	std::string sig = sign(privkey,test);

	bool is_valid = verifySig(pubkey,test,sig);
	std::cout << "pass: " << is_valid << std::endl;
	is_valid = verifySig(pubkey,ttest,sig);
	std::cout << "fail: " << is_valid << std::endl;


	unsigned char *t_one = (unsigned char*)malloc(512);
	unsigned char *t_two = (unsigned char*)malloc(512);

	sig = sign_bytes(privkey,t_one,512);
	is_valid = verifySig_bytes(pubkey,t_one,512,sig);
	std::cout << "pass: " << is_valid << std::endl;
	is_valid = verifySig_bytes(pubkey,t_two,512,sig);
	std::cout << "fail: " << is_valid << std::endl;
	*/


	/*
	std::string b = b64_encode(test,11);
	std::cout << b << std::endl;

	size_t len = 0;
	char *d = (char*)b64_decode(b,&len);
	std::cout << d << std::endl;
	*/

	/*
	// gen key
	std::string symkey = genRandString(32);
	std::cout << symkey << std::endl;

	std::string ciphertext = encryptSymKeyWithPubKey(pubkey, symkey, &len);

	std::string plaintext = decryptSymKeyWithPrivKey(privkey, ciphertext, len);
	std::cout << plaintext << std::endl;
	*/
	/*

	// encrypt key
	unsigned char *ciphertext = encryptWithPubKey(pubkey, symkey, &len);

	// turn key into hex stringstream
	std::stringstream ss;
	for(int i = 0; i < 256; i++) {
		ss << std::hex << (int)ciphertext[i] << " ";
	}

	// turn to stringstream -> string
	std::string s = ss.str();

	std::cout << "s: " << s << std::endl;

	std::istringstream hex_char_stream(s);
	std::vector<unsigned char> bytes;
	int c;
	while(hex_char_stream >> std::hex >> c) {
		bytes.push_back(c);
	}

	unsigned char *data = reinterpret_cast<unsigned char*>(bytes.data());
	std::cout << std::endl << data << std::endl;

	char *plaintext = decryptWithPrivKey(privkey, data, len);

	std::cout << plaintext << std::endl;
	*/

}
