#ifndef KEYDERIVATIONOPENSSL_H
#define KEYDERIVATIONOPENSSL_H

#ifdef WITH_OPENSSL

#include "KeyDerivation.h"
#include "openssl/evp.h"
#include "../Exception.h"

struct OpenSSLKeyDerivation {

private:

	friend class KeyDerivationOpenSSL;

	/** the open-SSL digest to use */
	const EVP_MD* digest;

public:

	/** ctor */
	OpenSSLKeyDerivation(const EVP_MD* digest) : digest(digest) {;}

};

/** available ciphers */
namespace OpenSSLKeyDerivations {
	const OpenSSLKeyDerivation SHA_256 =	{EVP_sha256()};
	const OpenSSLKeyDerivation SHA_512 =	{EVP_sha512()};
}



/** key-derivation using OpenSSL */
class KeyDerivationOpenSSL : public KeyDerivation {

private:

	/** digest configuration */
	OpenSSLKeyDerivation cfg;

	/** number of iterations */
	const int iter = 1024*256;

public:

	/** ctor */
	KeyDerivationOpenSSL(const OpenSSLKeyDerivation& cfg) : cfg(cfg) {
		;
	}

	void derive(const uint8_t* pass, const uint32_t passLen, const uint8_t* salt, const uint32_t saltLen, uint8_t* out, const uint32_t outLen) override {

		const int res = PKCS5_PBKDF2_HMAC((const char*)pass, passLen, salt, saltLen, iter, cfg.digest, outLen, out);
		if (res != 1) {throw Exception("error while deriving key");}

	}



};

#endif

#endif // KEYDERIVATIONOPENSSL_H
