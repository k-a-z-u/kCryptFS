#ifndef HELPER_H
#define HELPER_H

class Helper {
	
public:

	/** convert the given data into a hex-string */
	static inline std::string toHexStr(const uint8_t* data, const uint32_t len) {
		char out[len*2];
		for (uint32_t i = 0; i < len; i++)
        sprintf(out+i*2, "%02x", data[i]);
		return std::string(out, len*2);
	}
	
};

#endif // HELPER_H
