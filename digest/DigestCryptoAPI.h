#ifndef DIGEST_CRYPTO_API_H
#define DIGEST_CRYPTO_API_H

#ifdef WITH_KERNEL

#include <linux/if_alg.h>
#include <sys/socket.h>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <vector>
#include <iostream>
#include <string>

#include "../Exception.h"
#include "Digest.h"

/**
 * describes a crypto-api digest
 */
struct CryptoAPIDigest {

private:

	/** the digest's name */
	const std::string name;
	
	/** the digesst's output length */
	const uint32_t len;
	
public:
	
	/** ctor */
	CryptoAPIDigest(const std::string& name, const uint32_t len) : name(name), len(len) {;}
	
	/** get the digest's name */
	const std::string& getName() const {return name;}
	
	/** get the digest's output size */
	uint32_t getSize() const {return len;}

};

/** all available digests */
namespace CryptoAPIDigests {
	const CryptoAPIDigest SHA1 =	{"sha256", 20};
	const CryptoAPIDigest SHA256 =	{"sha256", 32};
	const CryptoAPIDigest SHA512 =	{"sha512", 64};
	const CryptoAPIDigest MD5 =		{"md5", 16};
}

/**
 * several digest-implementations based on the kernel's crypto API
 * NOTE: this class is NOT intended to be thread-safe!!
 */
class DigestCryptoAPI : public Digest {
	
private:

	/** handle to the configuration socket */
	int sckCfg;
	
	/** handle to the digest-socket */
	int sckDigest;
	
	/** the type of digest to use */
	const CryptoAPIDigest& type;
			
public:
	
	/** ctor with type */
	DigestCryptoAPI(const CryptoAPIDigest& type) : sckCfg(-1), sckDigest(-1), type(type) {
		init();
	}
	
	/** dtor */
	~DigestCryptoAPI() {
		destroy();
	}
	
	/** no copy */
	DigestCryptoAPI(const DigestCryptoAPI& c) = delete;
	
	/** no assign */
	void operator = (const DigestCryptoAPI& c) = delete;
	
	/** move */
	DigestCryptoAPI(DigestCryptoAPI&& c) : sckCfg(c.sckCfg), sckDigest(c.sckDigest), type(c.type) {
		c.sckCfg = -1;
		c.sckDigest = -1;
	}
	

	void hash(const uint8_t* in, const uint32_t inLen, uint8_t* out) override {
		
		// send data
		const ssize_t sent = send(sckDigest, in, inLen, MSG_DONTWAIT);
		if (sent != inLen)			{throw Exception("failed to start digest");}
  
		// get digest
		const ssize_t got = read(sckDigest, out, type.getSize());
		if (got != type.getSize())	{throw Exception("failed to read the digest result");}
		
	}
	
	void start() override {
		;
	}

	void append(const uint8_t* in, const uint32_t inLen, const bool finalize) override {
	
		// send data
		const int flags = (finalize) ? (0) : (MSG_MORE);
		const ssize_t sent = send(sckDigest, in, inLen, flags);
		if (sent != inLen)			{throw Exception("failed to start digest");}
	
	}
	
	void get(uint8_t* out) override {
	  
		// get digest
		const ssize_t got = read(sckDigest, out, type.getSize());
		if (got != type.getSize())	{throw Exception("failed to read the digest result");}
	
	}
	
	/** get the output-size for this digest */
	uint32_t getSize() const override {
		return type.getSize();
	}
	
private:
	
	/**
	 * NOT THREAD SAFE
	 */
	void init() {
				
		int res = 0;
		
		// what we want to use: sha-hash
		struct sockaddr_alg sa = {};
		sa.salg_family = AF_ALG;
		strcpy((char *)sa.salg_type, "hash");
		strcpy((char *)sa.salg_name, type.getName().c_str());		
		
		sckCfg = socket(AF_ALG, SOCK_SEQPACKET, 0);
		if (sckCfg < 0) {destroy(); throw Exception("could not create api-socket");}
		
		res = bind(sckCfg, (struct sockaddr*)&sa, sizeof(sa));
		if (res < 0) {destroy(); throw Exception("could not bind api-socket");}
				
		// setting the key to use (this means we get a HMAC)
		//const int key = 0;
		//const int keyLen = 4;
		//res = setsockopt(sckCfg, SOL_ALG, ALG_SET_KEY, &key, keyLen);
		//if (res < 0) {destroy(); throw Exception("could not set HMAC-key");}	
		
		// get a socket to access the configured algorithm
		sckDigest = accept(sckCfg, NULL, 0);
		if (sckDigest < 0) {destroy(); throw Exception("could not create Digest-socket");}
	
				
	}
			
	/** cleanup */
	void destroy() {
		if (sckCfg >= 0)	{close(sckCfg); sckCfg = -1;}
		if (sckDigest >= 0)	{close(sckDigest); sckDigest = -1;}	
	}
	
};


#endif

#endif //DIGEST_CRYPTO_API_H
