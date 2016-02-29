#ifndef ENCRYPTED_CONTAINER_H
#define ENCRYPTED_CONTAINER_H

#include "FileContainer.h"
#include "AlignedRegion.h"

#include "../iv/IVGeneratorFactory.h"

#include <mutex>
#include <thread>
#include <memory>

/**
 * the header at the beginning of every encrypted container.
 * is padded to 4096 bytes to ensure nice block-alignments
 */
struct EncryptedContainerHeader {
	uint32_t version;
	uint64_t fileSize;
	uint8_t pad[4084];
} __attribute__ ((__packed__));



/**
 * container implementation that will encrypt all written
 * and decrypt all read data using the cipher-setup
 * provided during construction
 */
class EncryptedContainer : public Container {

private:
	
	/** the underlying container to write to / read from */
	std::shared_ptr<Container> container;

	/** the file's encryption/decryption */
	std::shared_ptr<Cipher> cipher;
	
	/** init-vector generator */
	std::shared_ptr<IVGenerator> ivGen;
	
	/** the header at the beginning of the container */
	EncryptedContainerHeader header;

	/** thread-synchronization */
	std::mutex mtx;

public:
	
	/**
	 * ctor
	 * @param container the container to write to / read from
	 * @param cipher the cipher to use for encryption/decryption
	 * @param ivGen the iv-generator to use for encryption/decryption
	 */
	EncryptedContainer(std::shared_ptr<Container> container, std::shared_ptr<Cipher> cipher, std::shared_ptr<IVGenerator> ivGen) :
		container(container), cipher(cipher), ivGen(ivGen), header() {

		readHeader();

	}

	/** convenience CTOR for testing */
	EncryptedContainer(Container* container, Cipher* cipher, IVGenerator* ivGen) :
		container(container), cipher(cipher), ivGen(ivGen), header() {

		readHeader();

	}
	
	
	/** dtor */
	~EncryptedContainer() {
		writeHeader();
	}

	/** synchronize with the underlying container */
	int sync(const int datasync) override {
		writeHeader();
		return container->sync(datasync);
	}
	
	/** get the decrypted content-size */
	size_t getSize() const {
		return header.fileSize;
	}
	
	/**
	 * read 'size' bytes from the given 'offset' into the provided 'dst'
	 * returns the number of read bytes or a negative value in case of errors
	 */
	ssize_t read(uint8_t* dst, const size_t size, const off_t offset) override {
	
		//std::cout << "reading" << std::endl;

		AlignedRegion reg(offset, size);

		// read the aligned, encrypted region
		ssize_t read = doRead(reg.getEncBuffer(), reg.getSize(), reg.getStart());
		if (read < 0) {return -errno;}
		
		// could we read the whole requested region? if not, round "read" down to the nearest block-size
		// this works as offset is block-size aligned as well
		if ((size_t) read != reg.getSize()) {
			read = AlignedRegion::alignStart(read);
			//std::cout << "note: rounding down to: " << read << std::endl;
		}
		
		// nothing read?
		if (read == 0) {return 0;}

		// decrypt the whole region
		mtx.lock();
			reg.decrypt(*cipher, *ivGen);
		mtx.unlock();
		
		// calculate the to-be-fetched offset within the block-aligned region
		const size_t regOffset = (offset - reg.getStart());
		ssize_t outSize = std::min(read-regOffset, size);

		// prevent from reading beyond the payload
		if (reg.getStart() + regOffset + outSize > getSize()) {outSize = getSize() - regOffset - reg.getStart();}

		// something available at all?
		if (outSize > 0) { memcpy(dst, reg.getDecBuffer()+regOffset, outSize); }
		return (outSize > 0) ? (outSize) : (0);
		
	}
	
	/**
	 * write 'size' bytes to the given 'offset' by using the data from 'src'
	 * return the number of bytes written or a negative value in case of errors
	 */
	ssize_t write(const uint8_t* src, const size_t size, const off_t offset) override {
		
		// sanity check
		if (size > 1024*128) {throw Exception("large block request: " + std::to_string(size));}

		// align everything to the configured block-size
		AlignedRegion reg(offset, size);

		mtx.lock();
		
			// TODO: just like we only decrypt partially overwritten blocks, we could also modify
			// the read-operation to read only those blocks instead of the whole region
			// this should speed things up when overwriting parts of a file at unaligned boundaries

			// read the WHOLE aligned, encrypted region
			ssize_t read = doRead(reg.getEncBuffer(), reg.getSize(), reg.getStart());
			//std::cout << "offset:" << offset << " size:" << size << " read:" << read << std::endl;
			//std::cout << "\t" << "alignedS:" << reg.getStart() << " size:" << reg.getSize() << std::endl;
			if (read < 0) {read = 0;}	// ignore reading errors (reading beyond EOF, etc..)

			// to speed things up: decrypt only blocks that are partially overwritten
			if (read != 0) {
				//reg.decrypt(*cipher, *ivGen);
				reg.decryptForOverwrite(*cipher, *ivGen, offset, size);
			}

			// overwrite with the to-be-written data
			const ssize_t outStart = (offset - reg.getStart());
			memcpy(reg.getDecBuffer()+outStart, src, size);

			// re-encrypt the WHOLE region
			reg.encrypt(*cipher, *ivGen);

			// write-back the WHOLE region
			const ssize_t written = doWrite(reg.getEncBuffer(), reg.getSize(), reg.getStart());

			// sanity checks
			if (written == -1)						{throw Exception("writing failed");}
			if (written != (ssize_t)reg.getSize())	{throw Exception("could not write the whole region");}

			// update the file-size
			if ((offset+size) > header.fileSize) {
				header.fileSize = offset+size;
				writeHeader();		// performance penalty?! (benchmark: NO!)
			}
	
		mtx.unlock();

		// done
		return size;
	
	}

private:

	friend class FileContainer_HeaderUpdate_Test;

	/** writing. takes care of the header */
	ssize_t doWrite(const uint8_t* src, const size_t size, const off_t offset) {
		return container->write(src, size, offset+sizeof(header));
	}

	/** reading. takes care of the header */
	ssize_t doRead(uint8_t* dst, const size_t size, const off_t offset) {
		return container->read(dst, size, offset+sizeof(header));
	}
	
	/** read the container's header */
	void readHeader() {

		// for new files, reading the header may fail
		const ssize_t res = container->read((uint8_t*) &header, sizeof(header), 0);
		(void) res;

	}

	/** write the container's header */
	void writeHeader() const {

		// write the header and ensure success
		const ssize_t res = container->write((uint8_t*) &header, sizeof(header), 0);
		if (res != sizeof(header)) {
			throw Exception("error while writing header. result was: " + std::to_string(res), errno);
		}

	}

	/** set the encrypted content-size */
	void setSize(const size_t size) {
		this->header.fileSize = size;
	}

};

#endif // ENCRYPTED_CONTAINER_H
