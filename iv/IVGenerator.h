#ifndef IV_GENERATOR_H
#define IV_GENERATOR_H

/**
 * interface for all initialization-vector generators
 */
class IVGenerator {

public:

	virtual ~IVGenerator() {;}

	/** set-up the IV-generator */
	virtual void setup(const uint8_t* setup, const uint32_t setupLen) = 0;

	/** generate a new IV for the given file-offset into the provided buffer */
	virtual void getIV(const size_t pos, uint8_t* iv, const uint32_t ivLen) = 0;

};

#endif // IV_GENERATOR_H

