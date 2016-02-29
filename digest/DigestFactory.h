#ifndef DIGEST_FACTORY_H
#define DIGEST_FACTORY_H

#include "../Factory.h"
#include "Digest.h"
#include "DigestCryptoAPI.h"
#include "DigestOpenSSL.h"

#include <vector>

class DigestFactory : private Factory {
	
public:

	static Digest* getByName(const std::string& name) {

#ifdef WITH_KERNEL
		if ("kernel_sha1" == name	|| "sha1" == name)		{return new DigestCryptoAPI(CryptoAPIDigests::SHA1);}
		if ("kernel_sha256" == name	|| "sha256" == name)	{return new DigestCryptoAPI(CryptoAPIDigests::SHA256);}
		if ("kernel_sha512" == name	|| "sha512" == name)	{return new DigestCryptoAPI(CryptoAPIDigests::SHA512);}
		if ("kernel_md5" == name	|| "md5" == name)		{return new DigestCryptoAPI(CryptoAPIDigests::MD5);}
#endif

#ifdef WITH_OPENSSL
		if ("openssl_sha1" == name		|| "sha1" == name)		{return new DigestOpenSSL(OpenSSLDigests::SHA1);}
		if ("openssl_sha256" == name	|| "sha256" == name)	{return new DigestOpenSSL(OpenSSLDigests::SHA256);}
		if ("openssl_sha512" == name	|| "sha512" == name)	{return new DigestOpenSSL(OpenSSLDigests::SHA512);}
		if ("openssl_md5" == name		|| "md5" == name)		{return new DigestOpenSSL(OpenSSLDigests::MD5);}
#endif

		throw onNotFound("unsupported digest", name, getSupported());

	}


	/** get all supported digests */
	static std::vector<std::string> getSupported() {

		std::vector<std::string> res;

#ifdef WITH_OPENSSL
		res.push_back("openssl_sha1");
		res.push_back("openssl_sha256");
		res.push_back("openssl_sha512");
		res.push_back("openssl_md5");
#endif

#ifdef WITH_KERNEL
		res.push_back("kernel_sha1");
		res.push_back("kernel_sha256");
		res.push_back("kernel_sha512");
		res.push_back("kernel_md5");
#endif

		return res;

	}

};

#endif
