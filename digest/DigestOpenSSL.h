#ifndef DIGESTOPENSSL_H
#define DIGESTOPENSSL_H

#ifdef WITH_OPENSSL

#include "../Exception.h"
#include "Digest.h"

#include <openssl/evp.h>

/**
 * describes a crypto-api digest
 */
struct OpenSSLDigest {

private:

	friend class DigestOpenSSL;

	/** the digest */
	const EVP_MD* digest;

	/** the digesst's output length */
	const uint32_t len;

public:

	/** ctor */
	OpenSSLDigest(const EVP_MD* digest, const uint32_t len) : digest(digest), len(len) {;}

	/** get the digest's output size */
	uint32_t getSize() const {return len;}

};

/** all available digests */
namespace OpenSSLDigests {
	const OpenSSLDigest SHA1 =		{EVP_sha1(), 20};
	const OpenSSLDigest SHA256 =	{EVP_sha256(), 32};
	const OpenSSLDigest SHA512 =	{EVP_sha512(), 64};
	const OpenSSLDigest MD5 =		{EVP_md5(), 16};
}

/**
 * several digest-implementations based on the openSSL's crypto
 * NOTE: this class is NOT intended to be thread-safe!!
 */
class DigestOpenSSL : public Digest {

private:

	/** the type of digest to use */
	const OpenSSLDigest cfg;

	/** the digest */
	EVP_MD_CTX ctx;

public:

	/** ctor with type */
	DigestOpenSSL(const OpenSSLDigest& cfg) : cfg(cfg) {
		;
	}

	/** dtor */
	~DigestOpenSSL() {
		;
	}

	/** no copy */
	DigestOpenSSL(const DigestOpenSSL& c) = delete;

	/** no assign */
	void operator = (const DigestOpenSSL& c) = delete;


	void hash(const uint8_t* in, const uint32_t inLen, uint8_t* out) override {

		unsigned int outLen = 0;
		EVP_DigestInit(&ctx, cfg.digest);
		EVP_DigestUpdate(&ctx, in, inLen);
		EVP_DigestFinal(&ctx, out, &outLen);
		if (outLen != cfg.getSize()) {throw Exception("error while calculating digest");}

	}

	void start() override {
		EVP_DigestInit(&ctx, cfg.digest);
	}

	void append(const uint8_t* in, const uint32_t inLen, const bool finalize) override {
		(void) finalize;
		EVP_DigestUpdate(&ctx, in, inLen);
	}

	void get(uint8_t* out) override {
		unsigned int outLen = 0;
		EVP_DigestFinal(&ctx, out, &outLen);
		if (outLen != cfg.getSize()) {throw Exception("error while calculating digest");}
	}

	uint32_t getSize() const override {
		return cfg.len;
	}

};

#endif

#endif // DIGESTOPENSSL_H
