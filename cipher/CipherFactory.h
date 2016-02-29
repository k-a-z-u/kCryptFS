#ifndef CIPHER_FACTORY_H
#define CIPHER_FACTORY_H

#include "../Factory.h"
#include "Cipher.h"
#include "CipherCryptoAPI.h"
#include "CipherOpenSSL.h"

#include <vector>

class CipherFactory : private Factory {

public:

	/** get a cipher by its name */
	static Cipher* getByName(const std::string& name) {

#ifdef WITH_OPENSSL
		if ("openssl_aes_cbc_128" == name || "aes_cbc_128" == name)	{return new CipherOpenSSL(OpenSSLCiphers::AES_CBC_128);}
		if ("openssl_aes_cbc_192" == name || "aes_cbc_192" == name)	{return new CipherOpenSSL(OpenSSLCiphers::AES_CBC_192);}
		if ("openssl_aes_cbc_256" == name || "aes_cbc_256" == name)	{return new CipherOpenSSL(OpenSSLCiphers::AES_CBC_256);}
#endif

#ifdef WITH_KERNEL
		if ("kernel_aes_cbc_128" == name || "aes_cbc_128" == name)	{return new CipherCryptoAPI(CryptoAPICiphers::AES_CBC_128);}
		if ("kernel_aes_cbc_192" == name || "aes_cbc_192" == name)	{return new CipherCryptoAPI(CryptoAPICiphers::AES_CBC_192);}
		if ("kernel_aes_cbc_256" == name || "aes_cbc_256" == name)	{return new CipherCryptoAPI(CryptoAPICiphers::AES_CBC_256);}
#endif

		// none found
		throw onNotFound("unsupported cipher", name, getSupported());
		
	}

	/** get a cipher by its name and directly set its key */
	static Cipher* getByName(const std::string& name, const uint8_t* key, const uint32_t keyLen) {

		Cipher* cipher = getByName(name);
		cipher->setKey(key, keyLen);
		return cipher;

	}

	/** get all supported ciphers */
	static std::vector<std::string> getSupported() {

		std::vector<std::string> res;

#ifdef WITH_OPENSSL
		res.push_back("openssl_aes_cbc_128");
		res.push_back("openssl_aes_cbc_192");
		res.push_back("openssl_aes_cbc_256");
#endif

#ifdef WITH_KERNEL
		res.push_back("kernel_aes_cbc_128");
		res.push_back("kernel_aes_cbc_192");
		res.push_back("kernel_aes_cbc_256");
#endif

		return res;

	}

};

#endif //CIPHER_FACTORY_H
