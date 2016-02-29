#ifndef KEYS_H
#define KEYS_H

#include <termios.h>
#include <unistd.h>
#include <memory>

#include "Log.h"
#include "Exception.h"
#include "Helper.h"
#include "Configuration.h"
#include "cipher/CipherFactory.h"
#include "derivation/KeyDerivationFactory.h"

#define MAX_KEY_LEN		(1024/8)

/** struct to describe a key */
struct Key {
	
	uint8_t data[MAX_KEY_LEN];	// key data
	uint32_t len;				// key length
	
	Key() : len(0) {;}
	Key(const uint32_t len) : len(len) {;}
	
};

/**
 * handles:
 *  - user-password-input
 *  - key generation
 *  - key storage
 */
class Keys {

private:

	/** key to encrypt/decrypt file-data */
	Key keyData;

	/** key to encrypt/decrypt file-names */
	Key keyNames;

public:


	/** ctor */
	Keys() {
		;
	}
		
	/** get the key to encrypt/decrypt file-data */
	const Key& getFileDataKey() {return keyData;}
	
	/** get the key to encrypt/decrypt file-names */
	const Key& getFileNameKey() {return keyNames;}
	

	/** ask the user to enter his passwords and derive (strong) keys from it */
	void askForPasswords(const Configuration& cfg) {
		
		// allocate space for the keys
		keyData = Key(cfg.getCipherFileData()->getKeyLength());
		keyNames = Key(cfg.getCipherFileNames()->getKeyLength());

		// get the desired key-derivation
		std::shared_ptr<KeyDerivation> keyDeriv(cfg.getKeyDerivation());
		
		// ask the user for the password to encrypt file-data
		const std::string dataPass = readPassword("file-data password");
		
		// ask the user for the password to encrypt file-names
		std::string namePass = readPassword("file-name password");
		
		// empty filename pass? use the same as for file-data
		if (namePass.empty()) {
			addLog("keys", "using the same password for file-name and file-data encryption");
			namePass = dataPass;
		}		
		
		// fixed-salts for key-deriviation
		const uint8_t saltData[] = {169, 207, 98,	40, 50, 38, 22, 11, 217, 69, 165, 211, 130, 101, 244, 35};
		const uint8_t saltName[] = {247, 193, 149, 73, 240, 9, 250, 139, 220, 189, 142, 60, 190, 149, 11, 7};
		
		// use password and salt to derive a strong 256-bit key
		addLog("keys", "deriving keys, this may take some time");
		keyDeriv->derive((uint8_t*)dataPass.data(), dataPass.length(), saltData, 16, keyData.data, keyData.len);
		keyDeriv->derive((uint8_t*)namePass.data(), namePass.length(), saltName, 16, keyNames.data, keyNames.len);
		addLog("keys", "keys created");
		
	}

private:
	
	/** read a password from std-in */
	static std::string readPassword(const std::string& desc) {
		showEcho(false);
		std::string passwd;
		std::cout << desc << ": ";
		std::getline( std::cin, passwd );
		std::cout << std::endl;
		showEcho(true);
		return passwd;
	}
	
	/** enable/disable echo on std-in */
	static void showEcho(const bool enable) {

		struct termios tty;
		tcgetattr(STDIN_FILENO, &tty);
		if( !enable )	{tty.c_lflag &= ~ECHO;}
		else			{tty.c_lflag |=  ECHO;}

		(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);

	}
	
};

#endif //KEYS_H
