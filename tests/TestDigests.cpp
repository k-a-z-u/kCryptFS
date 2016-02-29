#include "Tests.h"

#ifdef WITH_TESTS

void _testMD5(Digest* digest) {
	uint8_t out[16];
	digest->hash((uint8_t*)"lorem ipsum", 11, out);
	ASSERT_EQ("80a751fde577028640c419000e33eba6", Helper::toHexStr(out, 16));
}

void _testSHA256(Digest* digest) {
	uint8_t out[16];
	digest->hash((uint8_t*)"lorem ipsum", 11, out);
	ASSERT_EQ("5e2bf57d3f40c4b6df69daf1936cb766f832374b4fc0259a7cbff06e2f70f269", Helper::toHexStr(out, 32));
}

void _testSHA512(Digest* digest) {
	uint8_t out[16];
	digest->hash((uint8_t*)"lorem ipsum", 11, out);
	ASSERT_EQ("f80eebd9aabb1a15fb869ed568d858a5c0dca3d5da07a410e1bd988763918d973e344814625f7c844695b2de36ffd27af290d0e34362c51dee5947d58d40527a", Helper::toHexStr(out, 64));
}

#ifdef WITH_OPENSSL
TEST(DigestOpenSSL, MD5) {
	DigestOpenSSL md5(OpenSSLDigests::MD5); _testMD5(&md5);
}
TEST(DigestOpenSSL, SHA256) {
	DigestOpenSSL sha(OpenSSLDigests::SHA256); _testSHA256(&sha);
}
TEST(DigestOpenSSL, SHA512) {
	DigestOpenSSL sha(OpenSSLDigests::SHA512); _testSHA512(&sha);
}
#endif

#ifdef WITH_KERNEL
TEST(DigestCryptoAPI, MD5) {
	DigestCryptoAPI md5(CryptoAPIDigests::MD5); _testMD5(&md5);
}
TEST(DigestCryptoAPI, SHA256) {
	DigestCryptoAPI sha(CryptoAPIDigests::SHA256); _testSHA256(&sha);
}
TEST(DigestCryptoAPI, SHA512) {
	DigestCryptoAPI sha(CryptoAPIDigests::SHA512); _testSHA512(&sha);
}
#endif


#endif
