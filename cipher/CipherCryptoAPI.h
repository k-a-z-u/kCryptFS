#ifndef CIPHER_CRYPTO_API
#define CIPHER_CRYPTO_API

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
#include "Cipher.h"

#define SOL_ALG 279 

/**
 * describes a cipher
 */
struct CryptoAPICipher {

private:

	/** the cipher's name */
	const std::string name;
	
	/** the cipher's description */
	const std::string desc;
	
	/** the cipher's key length */
	const uint32_t keyLen;
	
	/** the cipher's IV length */
	const uint32_t ivLen;
	
public:
	
	/** ctor */
	CryptoAPICipher(const std::string& name, const std::string& desc, const uint32_t keyLen, const uint32_t ivLen) :
		name(name), desc(desc), keyLen(keyLen), ivLen(ivLen) {;}
	
	/** get the cipher's name */
	const std::string& getName() const {return name;}
	
	/** get the cipher's description */
	const std::string& getDesc() const {return desc;}
	
	/** get the ciphers's key length */
	uint32_t getKeyLength() const {return keyLen;}
	
	/** get the cipher's IV-length */
	uint32_t getIVLength() const {return ivLen;}

};


/** available ciphers */
namespace CryptoAPICiphers {
	const CryptoAPICipher AES_CBC_128 =	{"cbc(aes)", "aes_cbc_128", 128/8, 128/8};
	const CryptoAPICipher AES_CBC_192 =	{"cbc(aes)", "aes_cbc_192", 192/8, 128/8};
	const CryptoAPICipher AES_CBC_256 =	{"cbc(aes)", "aes_cbc_256", 256/8, 128/8};
}

/**
 * provides encryption/decryption using the kernel's crypto API
 * NOTE: this class is NOT intended to be thread-safe!!
 */
class CipherCryptoAPI : public Cipher {
	
private:

	/** handle to the configuration socket */
	int sckCfg;
	
	/** handle to the AES-socket */
	int sckCipher;
	
	/** cipher description */
	CryptoAPICipher type;
			
public:
	
	/** ctor */
	CipherCryptoAPI(const CryptoAPICipher& type) : sckCfg(-1), sckCipher(-1), type(type) {
		init();
	}
	
	/** dtor */
	~CipherCryptoAPI() {
		destroy();
	}
	
	/** no copy */
	CipherCryptoAPI(const CipherCryptoAPI& c) = delete;
	
	/** no asignment */
	void operator = (const CipherCryptoAPI& o) = delete;
		

	/** get the cipher's required key length */
	uint32_t getKeyLength() const override {
		return type.getKeyLength();
	}
	
	/** get the cipher's required IV length */
	uint32_t getIVLength() const override {
		return type.getIVLength();
	}

	/** NOT THREAD SAFE encrypt the given input data into the provided output buffer */
	void encrypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t iv_length) override {
		crypt(in, out, length, iv, iv_length, ALG_OP_ENCRYPT);
	}

	/** NOT THREAD SAFE decrypt the given input data into the provided output buffer */
	void decrypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t iv_length) override {
		crypt(in, out, length, iv, iv_length, ALG_OP_DECRYPT);
	}
	
//	/**
//	 * NOT THREAD SAFE
//	 * encrypt the given input data into the provided output buffer
//	 * returns the number of bytes written to the output
//	 * returns a negative number in case of errors
//	 */
//	inline void encrypt(const uint8_t* in, uint8_t* out, const uint32_t length) {
//		crypt(ALG_OP_ENCRYPT, in, out, length);
//	}

//	/**
//	 * NOT THREAD SAFE
//	 * decrypt the given input data into the provided output buffer
//	 * returns the number of bytes written to the output
//	 * returns a negative number in case of errors
//	 */
//	inline void decrypt(const uint8_t* in, uint8_t* out, const uint32_t length) {
//		crypt(ALG_OP_DECRYPT, in, out, length);
//	}
	
	/**
	 * set the cipher's key
	 */
	void setKey(const uint8_t* key, const uint32_t keyLen) override {

		// sanity check
		if (keyLen != type.getKeyLength()) {
			throw Exception("unsupported key length: " + std::to_string(keyLen));
		}

		// setting the key to use for the encryption
		// NOTE: may this one also be called AFTER accept() is used?!
		int res = setsockopt(sckCfg, SOL_ALG, ALG_SET_KEY, key, keyLen);
		if (res < 0) {destroy(); throw Exception("could not set cipher-key");}

	}

//	/**
//	 * set the initialization-vector to use for the next requests.
//	 * return 0 if everything was fine.
//	 * returns -1 in case of errors
//	 */
//	void setIV(const uint8_t* iv, const uint32_t ivLen) {
		
//		// sanity check
//		if (ivLen != type.getIVLength()) {
//			throw Exception("unsupported IV-length: " + std::to_string(ivLen));
//		}
		
//		// message data buffer
//		char cbuf[CMSG_SPACE(4+ivLen)] __attribute__((__aligned__(8192))) = {};
		
//		// construct the to-be-send message using this buffer
//		struct msghdr msg = {};
//		msg.msg_control = cbuf;
//		msg.msg_controllen = sizeof(cbuf);
		
//		// msg content: set the initialization-vector
//		struct cmsghdr* cmsg;
//		cmsg = CMSG_FIRSTHDR(&msg);
//		cmsg->cmsg_level = SOL_ALG;
//		cmsg->cmsg_type = ALG_SET_IV;
//		cmsg->cmsg_len = CMSG_LEN(4+ivLen);
		
//		// set the intialization-vector within the message
//		struct af_alg_iv* alg_iv;
//		alg_iv = (af_alg_iv*)CMSG_DATA(cmsg);
//		alg_iv->ivlen = ivLen;
//		memcpy(alg_iv->iv, iv, ivLen);
		
//		// send and check
//		int len = sendmsg(sckCipher, &msg, 0);
//		if (len < 0) {throw Exception("failed to set IV");}
		
//	}

private:
	
	/**
	 * NOT THREAD SAFE
	 * cipher initialization
	 * establishes a socket connection, selects the cipher,
	 * sets the cipher's key
	 * gets a socket to use the configured cipher
	 */
	void init() {
				
		int res = 0;
		
		// what we want to use: a symmetric cipher of type AES
		struct sockaddr_alg sa = {};
		sa.salg_family = AF_ALG;
		strcpy((char *)sa.salg_type, "skcipher");
		strcpy((char *)sa.salg_name, type.getName().c_str());
		
		sckCfg = socket(AF_ALG, SOCK_SEQPACKET, 0);
		if (sckCfg < 0) {destroy(); throw Exception("could not create api-socket");}
		
		res = bind(sckCfg, (struct sockaddr*)&sa, sizeof(sa));
		if (res < 0) {destroy(); throw Exception("could not bind api-socket");}
				
		// get a socket to access the configured algorithm
		sckCipher = accept(sckCfg, NULL, 0);
		if (sckCipher < 0) {destroy(); throw Exception("could not create cipher-socket");}
				
	}
	
//	/**
//	 * NOT THREAD SAFE
//	 * encrypt/decrypt the given input into the provided output.
//	 * returns the number of bytes written to the output
//	 * returns a negative number in case of errors
//	 */
//	inline void crypt(const int mode, const uint8_t* in, uint8_t* out, const uint32_t inLen) {
				
//		// sanity check (>= 256*1024 seems to lead to deadlocks?!)
//		if (inLen >= 256*1024) {throw Exception("input too long");}
		
//		// message data buffer
//		char cbuf[CMSG_SPACE(4)] __attribute__((__aligned__(8192))) = {};
		
//		// data
//		struct iovec iov;
//		iov.iov_base = (void*) (uintptr_t)in;
//		iov.iov_len = inLen;
		
//		// construct the to-be-send message using this buffer
//		struct msghdr msg = {};
//		msg.msg_control = cbuf;
//		msg.msg_controllen = sizeof(cbuf);
//		msg.msg_iov = &iov;
//		msg.msg_iovlen = 1;
		
//		// msg content: set the direction (encryption/decryption)
//		struct cmsghdr* cmsg;
//		cmsg = CMSG_FIRSTHDR(&msg);
//		cmsg->cmsg_level = SOL_ALG;
//		cmsg->cmsg_type = ALG_SET_OP;
//		cmsg->cmsg_len = CMSG_LEN(4);
//		*(__u32 *)CMSG_DATA(cmsg) = mode;		// ALG_OP_DECRYPT vs. ALG_OP_DECRYPT
				
//		// send request and check
//		int len = sendmsg(sckCipher, &msg, 0);
//		if (len < 0) {throw Exception("failed to start encryption/decrytion");}
		
//		// read result and check
//		len = read(sckCipher, out, inLen);
//		if (len < 0) {throw Exception("failed to read the encryption/decryption result");}
				
//	}
		
	/** NOT THREAD SAFE perform encryption or decryption based on the given parameters */
	void crypt(const uint8_t* in, uint8_t* out, const uint32_t length, const uint8_t* iv, const uint32_t iv_length, const uint32_t direction) {
	
		if (!in || !out || !length)				{throw Exception("input, output or length is missing");}
		if (!iv || !iv_length)					{throw Exception("IV or IV-length is missing");}
		if (iv_length != type.getIVLength())	{throw Exception("invalid IV-length: " + std::to_string(iv_length));}
		
		int32_t len;
		struct iovec iov;
		struct af_alg_iv* alg_iv;
		struct msghdr msg = {};
		struct cmsghdr* cmsg;
				
		// buffer for 2 messages to the kernel
		// 1st: whether we want to encrypt or decrypt
		// 2nd: the initialization-vector
		// warning: thus buffer must be aligned! otherwise we get "error 14: bad address"
		const int sizeM1 = CMSG_SPACE(4);
		const int sizeM2 = CMSG_SPACE(4+16);
		char cbuf[sizeM1 + sizeM2] __attribute__((__aligned__(8192))) = {}; 

		// construct the to-be-send message using this buffer
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		// 1st msg content: set the direction (encryption/decryption)
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_OP;
		cmsg->cmsg_len = CMSG_LEN(4);
		*(__u32 *)CMSG_DATA(cmsg) = direction;		// ALG_OP_DECRYPT vs. ALG_OP_DECRYPT

		// 2nd msg content: set the initialization-vector
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(4+iv_length);
		alg_iv = (af_alg_iv*)CMSG_DATA(cmsg);
		alg_iv->ivlen = iv_length;
		memcpy(alg_iv->iv, iv, iv_length);

		// 3: attach the to-be-encrypted/decrypted data
		iov.iov_base = (void*) (uintptr_t)in;
		iov.iov_len = length;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
				
		// send the configuration including the to-be-encrypted/decrypted data
		len = sendmsg(sckCipher, &msg, 0);
		if (len != (ssize_t)length) {
			throw Exception("error while requesting encryption/decryption of " + std::to_string(length) + " bytes");
		}
		
		// read encryption/decryption result
		len = read(sckCipher, out, length);
		if (len != (ssize_t)length) {
			throw Exception("error while reading encryption/decription result");
		}

	}
	
	/** cleanup */
	void destroy() {
		if (sckCfg >= 0)	{close(sckCfg); sckCfg = -1;}
		if (sckCipher >= 0)	{close(sckCipher); sckCipher = -1;}	
	}
		
};

#endif

#endif //CIPHER_CRYPTO_API
