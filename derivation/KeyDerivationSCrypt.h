#ifndef KEYDERIVATIONSCRYPT_H
#define KEYDERIVATIONSCRYPT_H

#ifdef WITH_SCRYPT

#include <libscrypt.h>

/** key-derivation using SCrypt */
class KeyDerivationSCrypt : public KeyDerivation {

public:

	/** ctor */
	KeyDerivationSCrypt() {
		;
	}

	void derive(const uint8_t* pass, const uint32_t passLen, const uint8_t* salt, const uint32_t saltLen, uint8_t* out, const uint32_t outLen) override {


		static constexpr int _SCRYPT_N = 16384;
		static constexpr int _SCRYPT_r = 8;
		static constexpr int _SCRYPT_p = 16;

		const int res = libscrypt_scrypt(pass, passLen, salt, saltLen, _SCRYPT_N, _SCRYPT_r, _SCRYPT_p, out, outLen);
		if (res != 0) {throw Exception("error while creating scrypt hash");}

	}



};

#endif

#endif // KEYDERIVATIONSCRYPT_H
