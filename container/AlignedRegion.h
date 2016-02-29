#ifndef ALIGNED_REGION_H
#define ALIGNED_REGION_H

#include "../cipher/Cipher.h"
#include "../iv/IVGeneratorFactory.h"


namespace Settings {

	/** the block-size to use for CBC encryption. each block has its own IV */
	const constexpr int BLK_SIZE = 4096;

	/** the length of the initialization-vector to use */
	const constexpr int MAX_IV_LEN = 64;

}

/**
 * helper class to ensure we always work an aligned blocks.
 * those are needed for the cipher to work as expected.
 *
 * NOT THREAD SAFE (depends on cipher and iv-generator)
 */
class AlignedRegion {
		
	/** start-address. aligned to BLK_SIZE */
	const off_t alignedStart;
	
	/** end-address. aligned to BLK_SIZE */
	const off_t alignedEnd;

	/** size of the region between start and end */
	const size_t alignedSize;
	
	/** buffer to hold both, encrypted and decrypted data for above region-size */
	uint8_t* buffer;
	
public:

	/** align the given start-address to multiples of BLK_SIZE */
	static inline off_t alignStart(const off_t unalignedStart)						{return (unalignedStart / Settings::BLK_SIZE) * Settings::BLK_SIZE;}

	/** align the given end-address to multiples of BLK_SIZE */
	static inline off_t alignEnd(const off_t unalignedStart, const size_t size) 	{return ((size + unalignedStart - 1) / Settings::BLK_SIZE + 1) * Settings::BLK_SIZE;}
	
public:	
	
	/** ctor */
	AlignedRegion(const off_t unalignedStart, const size_t size) :
		alignedStart(alignStart(unalignedStart)),
		alignedEnd(alignEnd(unalignedStart, size)),
		alignedSize(alignedEnd-alignedStart) {

		// allocate buffer for both: the encrypted AND decrypted data
		// note: using 4k aligned buffers did not yield any performance increase
		buffer = (uint8_t*) malloc(getSize() * 2);
		if (buffer == nullptr) {throw Exception("out-of-memory");}

	}

	/** deleted copy ctor */
	AlignedRegion(const AlignedRegion&) = delete;
	
	/** deleted assignment */
	void operator = (const AlignedRegion&) = delete;
		
	/** dtor */
	~AlignedRegion() {
		free(buffer);
		buffer = nullptr;
	}
	


	/** get the region's (aligned) starting position */
	off_t getStart() const {
		return alignedStart;
	}
	
	/** get the region's (aligned) size */
	size_t getSize() const {
		return alignedSize;
	}
	
	/** get a buffer to store the encpryted data to */
	uint8_t* getEncBuffer() {
		return buffer;									// first half of the buffer
	}
	
	/** get a buffer to store the decrypted data to */
	uint8_t* getDecBuffer() {
		return buffer + getSize();						// 2nd half of the buffer
	}
	
	/** decrypt the WHOLE data within the encryption buffer */
	void decrypt(Cipher& cipher, IVGenerator& ivGen) {
		uint8_t iv[Settings::MAX_IV_LEN];
		const uint32_t ivLen = cipher.getIVLength();
		for (size_t s = 0; s < getSize(); s += Settings::BLK_SIZE) {
			ivGen.getIV(alignedStart + s, iv, ivLen);
			cipher.decrypt(getEncBuffer()+s, getDecBuffer()+s, Settings::BLK_SIZE, iv, ivLen);
		}
	}

	/**
	 * to speed thing up:
	 * decrypt only the blocks that will not be completely overwritten.
	 * when writing data, most blocks will be overwritten completely.
	 * decryption is only needed where blocks are overwritten partially.
	 *
	 * returns the number of decrypted blocks (for testing)
	 */
	int decryptForOverwrite(Cipher& cipher, IVGenerator& ivGen, const off_t writeStart, const size_t writeSize) {

		int blocks = 0;

		uint8_t iv[Settings::MAX_IV_LEN];
		const uint32_t ivLen = cipher.getIVLength();
		const off_t writeEnd = writeStart + writeSize;

		// partially overwriting the first block? -> decrypt it
		if (writeStart != alignedStart) {
			ivGen.getIV(alignedStart, iv, ivLen);
			cipher.decrypt(getEncBuffer(), getDecBuffer(), Settings::BLK_SIZE, iv, ivLen);
			++blocks;
		}

		// if the whole aligned region contains only one block at all, and we already decrypted it, we are done
		if (getSize() == Settings::BLK_SIZE && blocks > 0) {return blocks;}

		// partially overwriting the last block -> decrypt it
		if (writeEnd != alignedEnd) {
			const off_t o = getSize()-Settings::BLK_SIZE;
			ivGen.getIV(alignedStart+o, iv, ivLen);
			cipher.decrypt(getEncBuffer()+o, getDecBuffer()+o, Settings::BLK_SIZE, iv, ivLen);
			++blocks;
		}

		// for testing
		return blocks;

	}

	/** encrypt the WHOLE data within the decryption buffer */
	void encrypt(Cipher& cipher, IVGenerator& ivGen) {
		uint8_t iv[Settings::MAX_IV_LEN];
		const uint32_t ivLen = cipher.getIVLength();
		for (size_t s = 0; s < getSize(); s += Settings::BLK_SIZE) {
			ivGen.getIV(alignedStart + s, iv, ivLen);
			cipher.encrypt(getDecBuffer()+s, getEncBuffer()+s, Settings::BLK_SIZE, iv, ivLen);
		}
	}
				
};

#endif //ALIGNED_REGION_H
