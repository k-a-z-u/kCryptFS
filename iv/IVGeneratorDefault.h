#ifndef IV_GEN_H
#define IV_GEN_H


#include "../digest/DigestFactory.h"
#include "../Exception.h"
#include "IVGenerator.h"

#include <memory>

/**
 * create initialization-vectors (IVs)
 * based on the SHA256 of the user's key
 * and the the requested sector:
 *		IV = SHA(SHA(key)+offset)
 */
class IVGeneratorDefault : public IVGenerator {

private:
		
	/** setup hash. max 64 bytes (a little room after the hash) */
	uint8_t setupHash[64];
	
	/** the digest to use */
	std::shared_ptr<Digest> digest;

public:

	/** ctor with the name of the digest to use */
	IVGeneratorDefault(const std::string& digestName) : digest(DigestFactory::getByName(digestName)) {
		;
	}

	/** ctor with the digest to use */
	IVGeneratorDefault(const std::shared_ptr<Digest>& digest) : digest(digest) {
		;
	}
	
	/** no copy */
	IVGeneratorDefault(const IVGeneratorDefault& c) = delete;
	
	/** no assign */
	void operator = (const IVGeneratorDefault& c) = delete;
	


	/** initialize the generator (once) */
	void setup(const uint8_t* setup, const uint32_t setupLen) override {

		if (setupLen > 32) {throw Exception("setup-length must be max 32 byte");}

		// hash the secret key (once)
		digest->hash(setup, setupLen, setupHash);

	}
	
	/** NOT THREAD SAFE! generate a new IV for the given file-offset */
	void getIV(const size_t pos, uint8_t* iv, const uint32_t ivLen) override {
		
		//if (ivLen != 16) {throw Exception("only 128Bit IV supported");}
		
		// temporal store
		uint8_t tmpIV[64];

		// quite hacky: we append the 8-byte position after the end of the user-key (unused space)
		// definitely NOT thread-safe.. but the hash itself isnt thread-safe either..
		// hash of the password hash and the offset: SHA(SHA(key)+offset)
		const uint32_t size = digest->getSize();
		memcpy(&setupHash[size], &pos, sizeof(pos));
		digest->hash(setupHash, size+sizeof(pos), tmpIV);
		
		// hash of the password hash and the offset: SHA(SHA(key)+offset)
		//sha.append(setupHash, size, false);
		//sha.append((uint8_t*)&pos, sizeof(size_t), true);
		//sha.get(tmpIV);
		
		// use only some parts of the 256Bit hash
		memcpy(iv, tmpIV, std::min(ivLen, size));
		
	}
	
};

#endif //IV_GEN_H
