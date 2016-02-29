#ifndef FACTORY_H
#define FACTORY_H

#include <vector>
#include <string>

#include "Exception.h"

/**
 * base-class for all factories:
 *	iv-generator
 *	ciphers
 *	digests
 *	...
 */
class Factory {

public:

	/** entity not found -> exit */
	static Exception onNotFound(const std::string& errMsg, const std::string& entity, const std::vector<std::string>& supported) {
		const std::string str = errMsg + " '" + entity + "'\n\tsupported:\n" + asString(supported);
		return Exception(str);
	}

	/** entity not given -> exit */
	static Exception onNotGiven(const std::string& errMsg, const std::vector<std::string>& supported) {
		const std::string str = errMsg + "\n\tsupported:\n" + asString(supported);
		return Exception(str);
	}

	/** helper method to convert all supported entities to a string */
	static std::string asString(const std::vector<std::string>& vec) {
		std::string res;
		for (const std::string& s : vec) {res += "\t" + s + "\n";}
		return res;
	}

};

#endif // FACTORY_H
