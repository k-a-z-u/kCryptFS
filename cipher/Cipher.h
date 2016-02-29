#ifndef CIPHER_H
#define CIPHER_H

#include <cstdint>

/** interface for all ciphers */
class Cipher {

public:

	/** dtor */
	virtual ~Cipher() {;}


	/** set the key to use for encryption */
	virtual void setKey(const uint8_t* key, const uint32_t keyLen) = 0;

	/** encrypt the given input data into the provided output buffer */
	virtual void encrypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t iv_length) = 0;

	/** ecrypt the given input data into the provided output buffer */
	virtual void decrypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t iv_length) = 0;
	

	/** get the length the cipher needs for its keys */
	virtual uint32_t getKeyLength() const = 0;

	/** get the length the cipher needs for its IV */
	virtual uint32_t getIVLength() const = 0;

};

#endif // CIPHER_H
