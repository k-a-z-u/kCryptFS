#ifndef KEYDERIVATION_H
#define KEYDERIVATION_H

#include <cstdint>

/** interface for all key-derivation functions */
class KeyDerivation {

public:

	/** use the given password and salt to derive a key of the requested length */
	virtual void derive(const uint8_t* pass, const uint32_t passLen, const uint8_t* salt, const uint32_t saltLen, uint8_t* out, const uint32_t outLen) = 0;


};

#endif // KEYDERIVATION_H
