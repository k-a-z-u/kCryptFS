#ifndef FILE_PATH_H
#define FILE_PATH_H

#include <string>
#include <memory>
#include <string.h>
#include <mutex>

#include "../cipher/Cipher.h"
#include "FilePathSplitter.h"

namespace Settings {

	/** maximum filename length (encrypted) */
	const int FILE_PATH_ML = 192;

	/** maximum filename length (unencrypted) */
	const int FILE_PATH_ML2 = FILE_PATH_ML/2;

	/** fixed initialization vector */
	const uint8_t FILE_PATH_IV[16] = {230, 81, 128, 34, 117, 47, 203, 62, 69, 45, 240, 49, 152, 122, 86, 190};

	/** fixed initialization vector length */
//	const uint32_t FILE_PATH_IV_LEN = 16;

}

/**
 * helperclass to
 * convert relative to absolute filenames
 * encrypt/decrypt relative filenames
 */
class FilePath {

//	friend class FileNames_EnDeCryptPath_Test;
//	friend class FileNames_EnDeCryptDotFolders_Test;

private:

	/** the encrypted path we have mounted */
	std::string mountSrcPath;
	
	/** the filename encryption */
	std::shared_ptr<Cipher> cipher;

	/** thread-sync */
	std::mutex mtx;
	
public:
	
	/** ctor */
	FilePath(const char* mountSrcPath, std::shared_ptr<Cipher> cipher) :  mountSrcPath(mountSrcPath), cipher(cipher) {
		;
	}
	
	
	/** get the given realtive file's full path name. this one does NOT decrypt the given relative filename */
	std::string getAbsolutePath(const char* relativePath) const {
		return mountSrcPath + relativePath;
	}
	
	/** get the given realtive file's full path name. thos one DOES decrypt the given realtive filename */
	std::string getAbsolutePathEnc(const char* relativePath) {
		return mountSrcPath + encryptRelativeFileName(relativePath);
	}
	
	/** decrypt the given (relative!) filename */
	std::string decryptRelativeFileName(const char* relativeFileName) {
		FilePathSplitter splt(relativeFileName);
		while (splt.hasNext()) {
			splt.setCur( decrypt(splt.next()) );
		}
		return splt.getPath();
		//std::vector<std::string> parts = split(relativeFileName);
		//const std::string res = implode(decrypt(parts));
		////std::cout << "#" << relativeFileName << " -> " << res << std::endl;
		//return res;
	}

	/** encrypt the given (relative!) filename */
	std::string encryptRelativeFileName(const char* relativeFileName) {
		FilePathSplitter splt(relativeFileName);
		while (splt.hasNext()) {
			splt.setCur( encrypt(splt.next()) );
		}
		return splt.getPath();
		//std::vector<std::string> parts = split(relativeFileName);
		//const std::string res = implode(encrypt(parts));
		////std::cout << "#" << relativeFileName << " -> " << res << std::endl;
		//return res;
	}

	/** encrypt one part of a filename (folder, name itself) */
	std::string encrypt(const std::string& str) {
		
		// skip always present folders
		if ("." == str || ".." == str) {return str;}
		
		// input filename (max 128 chars)
		uint8_t in[Settings::FILE_PATH_ML2] = {};
		memcpy(in, str.data(), str.length());
		
		mtx.lock();

		// get encrypted filename
		const uint32_t ivLen = cipher->getIVLength();
		uint8_t out[Settings::FILE_PATH_ML2];
		cipher->encrypt(in, out, Settings::FILE_PATH_ML2, Settings::FILE_PATH_IV, ivLen);
		
		mtx.unlock();

		// convert him to a hex string
		std::string hex; hex.resize(Settings::FILE_PATH_ML);
		byteToHex(out, Settings::FILE_PATH_ML2, (char*)hex.data());
		return hex;
		
	}
	
	/** decrypt one part of a filename (folder, name itself) */
	std::string decrypt(const std::string& str) {
		
		// skip always present folders
		if ("." == str || ".." == str) {return str;}
				
		// convert hexed input filename to raw bytes
		uint8_t in[Settings::FILE_PATH_ML2];
		hexToByte(str.data(), str.length(), in);
		
		mtx.lock();

		// decode the input filename
		const uint32_t ivLen = cipher->getIVLength();
		uint8_t out[Settings::FILE_PATH_ML2+1] = {};				// has space for one trailing zero
		cipher->decrypt(in, out, Settings::FILE_PATH_ML2, Settings::FILE_PATH_IV, ivLen);

		mtx.unlock();

		// done
		return std::string((const char*) out);
		
	}
	
private:
	
	/** convert from hex-string to a byte array */
	static void hexToByte(const char* chars, const int charsLen, uint8_t* bytes) {
		for(int i = 0; i < charsLen / 2; ++i) {
			bytes[i] = ((chars[i*2+0]-'a') << 0) | ((chars[i*2+1]-'a') << 4);
		}
	}
	
	/** convert from a byte-array to a hex string */
	static void byteToHex(const uint8_t* bytes, const int bytesLen, char* chars) {
		for (int i = 0; i < bytesLen; ++i) {
			chars[i*2+0] = 'a' + ((bytes[i] >> 0) & 0xF);
			chars[i*2+1] = 'a' + ((bytes[i] >> 4) & 0xF);
		}
	}
		
};



#endif //FILE_PATH_H
