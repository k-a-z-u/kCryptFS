#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <string>

#include "CMDLine.h"
#include "cipher/CipherFactory.h"
#include "derivation/KeyDerivationFactory.h"
#include "iv/IVGeneratorFactory.h"
#include "Log.h"

/**
 * module configuration:
 *  - cipher to use for filenames
 *  - cipher to use for file-data
 *  - IV-generator to use for file-data
 */
class Configuration {
	
	/** the cipher to use for file-data encryption/decryption */
	std::string cipherFileData;
	
	/** the cipher to use for file-name encryption/decryption */
	std::string cipherFileNames;

	/** the iv-generator to use */
	std::string ivGenerator;

	/** the key-derivation to use */
	std::string keyDerivation;
	
public:

	/** empty-ctor */
	Configuration() {
		;
	}

//	cipherFileData("aes_cbc_256"),
//	cipherFileNames("aes_cbc_256"),
//	ivGenerator("sha256"),
//	keyDerivation("pbkdf2_sha256") {

	/** ctor */
	Configuration(const CMDLine& cmd) {

		cipherFileData = cmd.getOption("cipher-filedata");
		getCipherFileData();

		cipherFileNames = cmd.getOption("cipher-filename");
		getCipherFileNames();

		ivGenerator = cmd.getOption("iv-gen");
		getIVGenerator(0, 0);

		keyDerivation = cmd.getOption("key-derivation");
		getKeyDerivation();

	}

	/** dump the configuration */
	void showSettings() {
		addLog("main", "file-name encryption: '"	+ cipherFileNames + "'");
		addLog("main", "file-data encryption: '"	+ cipherFileData + "'");
		addLog("main", "key-derivation: '"			+ keyDerivation + "'");
		addLog("main", "iv-generator: '"			+ ivGenerator + "'");
	}

	/** get the cipher to use for file-data */
	std::shared_ptr<Cipher> getCipherFileData() const {
		if (cipherFileData.empty()) {throw Factory::onNotGiven("no --cipher-filedata given", CipherFactory::getSupported());}
		return std::shared_ptr<Cipher>(CipherFactory::getByName(cipherFileData));
	}

	/** get the cipher to use for file-data */
	std::shared_ptr<Cipher> getCipherFileData(const uint8_t* key, const uint32_t keyLen) const {
		if (cipherFileData.empty()) {throw Factory::onNotGiven("no --cipher-filedata given", CipherFactory::getSupported());}
		return std::shared_ptr<Cipher>(CipherFactory::getByName(cipherFileData, key, keyLen));
	}


	/** get the cipher to use for file-names */
	std::shared_ptr<Cipher> getCipherFileNames() const {
		if (cipherFileNames.empty()) {throw Factory::onNotGiven("no --cipher-filename given", CipherFactory::getSupported());}
		return std::shared_ptr<Cipher>(CipherFactory::getByName(cipherFileNames));
	}

	/** get the cipher to use for file-names */
	std::shared_ptr<Cipher> getCipherFileNames(const uint8_t* key, const uint32_t keyLen) const {
		if (cipherFileNames.empty()) {throw Factory::onNotGiven("no --cipher-filename given", CipherFactory::getSupported());}
		return std::shared_ptr<Cipher>(CipherFactory::getByName(cipherFileNames, key, keyLen));
	}


	/** get the key-derivation algorithm */
	std::shared_ptr<KeyDerivation> getKeyDerivation() const {
		if (keyDerivation.empty()) {throw Factory::onNotGiven("no --key-derivation given", KeyDerivationFactory::getSupported());}
		return std::shared_ptr<KeyDerivation>(KeyDerivationFactory::getByName(keyDerivation));
	}

	/** get the iv-generator to use */
	std::shared_ptr<IVGenerator> getIVGenerator(const uint8_t* setup, const uint32_t setupLen) const {
		if (ivGenerator.empty()) {throw Factory::onNotGiven("no --iv-gen given", IVGeneratorFactory::getSupported());}
		return std::shared_ptr<IVGenerator>(IVGeneratorFactory::getByName(ivGenerator, setup, setupLen));
	}



};

#endif //CONFIGURATION_H
