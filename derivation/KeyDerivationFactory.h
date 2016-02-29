#ifndef KEYDERIVATIONFACTORY_H
#define KEYDERIVATIONFACTORY_H

#include "../Factory.h"
#include "KeyDerivation.h"
#include "KeyDerivationOpenSSL.h"
#include "KeyDerivationSCrypt.h"



class KeyDerivationFactory : private Factory {

public:

	/** get a key-derivation by its name */
	static KeyDerivation* getByName(const std::string& name) {

#ifdef WITH_OPENSSL
		if ("openssl_pbkdf2_sha256" == name || "pbkdf2_sha256" == name)	{return new KeyDerivationOpenSSL(OpenSSLKeyDerivations::SHA_256);}
		if ("openssl_pbkdf2_sha512" == name || "pbkdf2_sha512" == name)	{return new KeyDerivationOpenSSL(OpenSSLKeyDerivations::SHA_256);}
#endif

#ifdef WITH_SCRYPT
		if ("scrypt" == name)											{return new KeyDerivationSCrypt();}
#endif

		// none found
		throw onNotFound("unsupported key-derivation", name, getSupported());

	}

	/** get all supported ciphers */
	static std::vector<std::string> getSupported() {

		std::vector<std::string> res;

#ifdef WITH_OPENSSL
		res.push_back("openssl_pbkdf2_sha256");
		res.push_back("openssl_pbkdf2_sha512");
#endif

#ifdef WITH_SCRYPT
		res.push_back("scrypt");
#endif

		return res;

	}

};

#endif // KEYDERIVATIONFACTORY_H
