#include "Tests.h"

#ifdef WITH_TESTS

#include "../cipher/CipherOpenSSL.h"
#include "../cipher/CipherCryptoAPI.h"


void _testKeyChange(Cipher* cipher) {

	uint8_t key[32] = {13};
	uint32_t keyLen = cipher->getKeyLength();

	uint8_t iv[16] = {7};
	uint32_t ivLen = cipher->getIVLength();

	uint32_t length = 4096;
	uint8_t src[length];
	uint8_t enc[length];
	uint8_t dec[length];

	cipher->setKey(key, keyLen);

	// same key-> must match
	cipher->encrypt(src, enc, 4096, iv, ivLen);
	cipher->decrypt(enc, dec, 4096, iv, ivLen);
	ASSERT_EQ(0, memcmp(src, dec, length));

	// other decryption key -> decrypt again -> must not match
	key[0] = 1;
	cipher->setKey(key, keyLen);
	cipher->decrypt(enc, dec, 4096, iv, ivLen);
	ASSERT_NE(0, memcmp(src, dec, length));

	// new key but same for enc/dec -> must match
	key[0] = 2;
	cipher->encrypt(src, enc, 4096, iv, ivLen);
	cipher->decrypt(enc, dec, 4096, iv, ivLen);
	ASSERT_EQ(0, memcmp(src, dec, length));


}

void _testEnDeCrypt(Cipher* cEnc, Cipher* cDec) {

	uint8_t key[32] = {13};
	uint32_t keyLen = cEnc->getKeyLength();

	uint8_t iv[16] = {7};
	uint32_t ivLen = cEnc->getIVLength();

	// generate random data
	uint32_t length = 128*1024;
	uint8_t src[length], enc[length], dec[length];
	for (uint32_t i = 0; i < length; ++i) {src[i] = rand();}

	// set the key
	cEnc->setKey(key, keyLen);
	cDec->setKey(key, keyLen);

	// encrypt, decrypt, check
	cEnc->encrypt(src, enc, length, iv, ivLen);		// this one is thread safe: lock, set iv, encrypt, unlock
	cDec->decrypt(enc, dec, length, iv, ivLen);
	ASSERT_EQ(0, memcmp(src, dec, length));

	// change the IV and try decryption again
	iv[0] = 1;
	cDec->decrypt(enc, dec, length, iv, ivLen);
	ASSERT_NE(0, memcmp(src, dec, length));

	// encrypt, decrypt, check again
	cEnc->encrypt(src, enc, length, iv, ivLen);
	cDec->decrypt(enc, dec, length, iv, ivLen);
	ASSERT_EQ(0, memcmp(src, dec, length));

}

#ifdef WITH_OPENSSL
TEST(CipherOpenSSL, AES) {

	CipherOpenSSL aes128(OpenSSLCiphers::AES_CBC_128);
	CipherOpenSSL aes192(OpenSSLCiphers::AES_CBC_192);
	CipherOpenSSL aes256(OpenSSLCiphers::AES_CBC_256);

	_testKeyChange(&aes128);
	_testKeyChange(&aes192);
	_testKeyChange(&aes256);

	_testEnDeCrypt(&aes128, &aes128);
	_testEnDeCrypt(&aes192, &aes192);
	_testEnDeCrypt(&aes256, &aes256);

}
#endif

#ifdef WITH_KERNEL
TEST(CipherCryptoAPI, AES) {

	CipherCryptoAPI aes128(CryptoAPICiphers::AES_CBC_128);
	CipherCryptoAPI aes192(CryptoAPICiphers::AES_CBC_192);
	CipherCryptoAPI aes256(CryptoAPICiphers::AES_CBC_256);

	_testKeyChange(&aes128);
	_testKeyChange(&aes192);
	_testKeyChange(&aes256);

	_testEnDeCrypt(&aes128, &aes128);
	_testEnDeCrypt(&aes192, &aes192);
	_testEnDeCrypt(&aes256, &aes256);

}
#endif

#ifdef WITH_KERNEL
#ifdef WITH_OPENSSL
TEST(CipherCross, AES) {

	CipherOpenSSL	aes256a(OpenSSLCiphers::AES_CBC_256);
	CipherCryptoAPI aes256b(CryptoAPICiphers::AES_CBC_256);

	// use A to encrypt, B to decrypt, and vice versa
	_testEnDeCrypt(&aes256a, &aes256b);
	_testEnDeCrypt(&aes256b, &aes256a);

}
#endif
#endif




#endif
