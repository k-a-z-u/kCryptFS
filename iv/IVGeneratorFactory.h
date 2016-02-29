#ifndef IVGENERATORFACTORY_H
#define IVGENERATORFACTORY_H

#include <string>
#include "IVGenerator.h"
#include "IVGeneratorDefault.h"

#include "../Factory.h"

class IVGeneratorFactory : private Factory {

public:

	/** get an inititalization-vector generator by its name */
	static IVGenerator* getByName(const std::string& name, const uint8_t* setup, const uint32_t setupLen) {

//		if		("sha1" == name)	{IVGenerator* gen = new IVGeneratorDefault("sha1");		gen->setup(setup, setupLen); return gen;}
//		else if	("sha256" == name)	{IVGenerator* gen = new IVGeneratorDefault("sha256");	gen->setup(setup, setupLen); return gen;}
//		else if	("sha512" == name)	{IVGenerator* gen = new IVGeneratorDefault("sha512");	gen->setup(setup, setupLen); return gen;}
//		else if	("md5" == name)		{IVGenerator* gen = new IVGeneratorDefault("md5");		gen->setup(setup, setupLen); return gen;}

		Digest* digest = DigestFactory::getByName(name);
		IVGenerator* gen = new IVGeneratorDefault(std::shared_ptr<Digest>(digest));
		gen->setup(setup, setupLen);
		return gen;

		//throw onNotFound("unsupported iv-generator", name, getSupported());

	}

	/** supported is everything available from the DigestFactory */
	static std::vector<std::string> getSupported() {
		return DigestFactory::getSupported();
	}

};

#endif // IVGENERATORFACTORY_H

