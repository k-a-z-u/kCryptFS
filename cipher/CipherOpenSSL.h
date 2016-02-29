#ifndef CIPHEROPENSSL_H
#define CIPHEROPENSSL_H

#ifdef WITH_OPENSSL

#include "Cipher.h"
#include <string>
#include <openssl/evp.h>

struct OpenSSLCipher {

private:

	friend class CipherOpenSSL;

	/** the open-SSL cipher to use */
	const EVP_CIPHER* cipher;

	/** the cipher's key length */
	const uint32_t keyLen;

	/** the cipher's IV length */
	const uint32_t ivLen;

public:

	/** ctor */
	OpenSSLCipher(const EVP_CIPHER* cipher, const uint32_t keyLen, const uint32_t ivLen) : cipher(cipher), keyLen(keyLen), ivLen(ivLen) {;}

};

/** available ciphers */
namespace OpenSSLCiphers {
	const OpenSSLCipher AES_CBC_128 =	{EVP_aes_128_cbc(), 128/8, 128/8};
	const OpenSSLCipher AES_CBC_192 =	{EVP_aes_192_cbc(), 192/8, 128/8};
	const OpenSSLCipher AES_CBC_256 =	{EVP_aes_256_cbc(), 256/8, 128/8};
}

class CipherOpenSSL : public Cipher {

private:

	/** the current key (if any) */
	uint8_t key[64];

	/** configuration */
	OpenSSLCipher cfg;

	EVP_CIPHER_CTX dec;
	EVP_CIPHER_CTX enc;

public:

	/** ctor */
	CipherOpenSSL(const OpenSSLCipher& cfg) : key(), cfg(cfg) {

		 EVP_CIPHER_CTX_init(&dec);
		 EVP_CIPHER_CTX_init(&enc);

	}

	/** no copy */
	CipherOpenSSL(const CipherOpenSSL& c) = delete;

	/** no assign */
	void operator = (const CipherOpenSSL& c) = delete;


	/** set the key to use for encryption */
	virtual void setKey(const uint8_t* key, const uint32_t keyLen) {
		if (keyLen != cfg.keyLen) {throw Exception("invalid key length");}
		memcpy(this->key, key, keyLen);
	}

	/** encrypt the given input data into the provided output buffer */
	virtual void encrypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t ivLength) {

		EVP_EncryptInit_ex(&enc, cfg.cipher, nullptr, key, iv);		// set key and IV
		EVP_CIPHER_CTX_set_padding(&enc, 0);						// do NOT add a padding
		if (EVP_CIPHER_CTX_key_length(&enc) != (int)cfg.keyLen)		{throw Exception("invalid key length");}
		if (EVP_CIPHER_CTX_iv_length(&enc) != (int)ivLength)		{throw Exception("invlaid IV length");}

		int outLen = 0;
		EVP_EncryptUpdate(&enc, out, &outLen, in, length);
		if (outLen != (int)length) {throw Exception("error while encrypting data");}
		//EVP_EncryptFinal(&enc, out, &outLen);						// needed only for padding?

	}

	/** ecrypt the given input data into the provided output buffer */
	virtual void decrypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t ivLength) {

		EVP_DecryptInit_ex(&dec, cfg.cipher, nullptr, key, iv);		// set key and IV
		EVP_CIPHER_CTX_set_padding(&dec, 0);						// do NOT check for padding
		if (EVP_CIPHER_CTX_key_length(&dec) != (int)cfg.keyLen)		{throw Exception("invalid key length");}
		if (EVP_CIPHER_CTX_iv_length(&dec) != (int)ivLength)		{throw Exception("invlaid IV length");}

		int outLen = 0;
		EVP_DecryptUpdate(&dec, out, &outLen, in, length);
		if (outLen != (int)length) {throw Exception("error while decrypting data");}
		//EVP_DecryptFinal(&dec, out, &outLen);						// needed only for padding?

	}


	/** get the length the cipher needs for its keys */
	virtual uint32_t getKeyLength() const {
		return cfg.keyLen;
	}


	/** get the length the cipher needs for its IV */
	virtual uint32_t getIVLength() const {
		return cfg.ivLen;
	}

};

#endif

#endif // CIPHEROPENSSL_H
