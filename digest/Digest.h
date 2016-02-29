#ifndef DIGEST_H
#define DIGEST_H

class Digest {
	
public:

	virtual ~Digest() {;}

	/** get the hash (digest) for the given input into the provided output buffer */
	virtual void hash(const uint8_t* in, const uint32_t inLen, uint8_t* out) = 0;
	

	/** start building a digest. followed by append() and get() */
	virtual void start() = 0;

	/** append data for hashing. do not yet receive the final output */
	virtual void append(const uint8_t* in, const uint32_t inLen, const bool finalize) = 0;
	
	/** finalize the digest calculation */
	virtual void get(uint8_t* out) = 0;
	

	/** get the output-size for this digest */
	virtual uint32_t getSize() const = 0;
	
};

#endif
