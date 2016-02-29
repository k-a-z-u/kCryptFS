#include "Tests.h"

#ifdef WITH_TESTS

#include "../derivation/KeyDerivationOpenSSL.h"
#include "../derivation/KeyDerivationSCrypt.h"

#ifdef WITH_OPENSSL

TEST(KeyDerivation, openSSL) {

	KeyDerivationOpenSSL sha256(OpenSSLKeyDerivations::SHA_256);
	KeyDerivationOpenSSL sha512(OpenSSLKeyDerivations::SHA_512);

	std::string pass = "helloWorld";
	uint8_t salt[] = {1,2,3,4,5,6,7,8};
	uint8_t out[128] = {0};

	sha256.derive((uint8_t*)pass.data(), pass.size(), salt, 8, out, 127);
	ASSERT_NE(0, out[126]);
	ASSERT_EQ(0, out[127]);

	sha256.derive((uint8_t*)pass.data(), pass.size(), salt, 8, out, 128);
	ASSERT_NE(0, out[126]);
	ASSERT_NE(0, out[127]);

	sha512.derive((uint8_t*)pass.data(), pass.size(), salt, 8, out, 128);

}

#endif


#ifdef WITH_SCRYPT

TEST(KeyDerivation, SCrypt) {

}

#endif

#endif
