// NOTES:
//
//	great tutorial for starters
//	https://www.cs.hmc.edu/~geoff/classes/hmc.cs135.201109/homework/fuse/fuse_doc.html
//
//	performance
//	http://fuse.996288.n3.nabble.com/Fuse-with-direct-io-option-does-not-work-via-Samba-td9047.html
//

#define FUSE_USE_VERSION 26
#include <fuse.h>


#include "FS.h"
#include "CMDLine.h"
#include "tests/Tests.h"

/** convert username to UID */
uid_t getUID(const std::string& user) {
	struct passwd* pwd = getpwnam(user.c_str());
	if (pwd == nullptr) {throw Exception("could not determin UID for user " + user);}
	return pwd->pw_uid;
}

/** print usage information */
void showUsage() {

	std::cout << "usage: kCryptFS [options] [mountEnc] [mountDec]" << std::endl;
	std::cout << std::endl;

	std::cout << "kCryptFS -test" << std::endl;
	std::cout << "\tjust run all test-cases and exit" << std::endl;
	std::cout << std::endl;

	std::cout << "kCryptFS [options] /path/encrypted /path/decrypted" << std::endl;
	std::cout << "\t-foreground    run in foreground" << std::endl;
	std::cout << "\t-log           enable logging to std::out" << std::endl;
	std::cout << "\t-allow-other   allow access to other users as well" << std::endl;
	std::cout << "\t-uid username  run under a different user" << std::endl;
	std::cout << "\t example" << std::endl;
	std::cout << "\t-foreground --cipher-filedata=openssl_aes_cbc_256 --cipher-filename=openssl_aes_cbc_256 \\" << std::endl;
	std::cout << "\t\t--key-derivation=openssl_pbkdf2_sha512 --iv-gen=openssl_sha256 /tmp/enc /tmp/dec" << std::endl;

}

/** start */
int main(int argc, char* argv[]) {
	    
	// at least one argument (the mode)
	if (argc < 2) { showUsage(); return -1; }

	// warnings
	if ((getuid() == 0) || (geteuid() == 0)) { addLog("main", "warning! running as root!"); }

	// parse cmd-line
	CMDLine args(argc, (const char**)argv);

	// run tests?
	if(args.hasSwitch("test")) {return runTests(0, nullptr);}

	// mount!

	// sanity check
	if (argc < 3) {showUsage(); return -1;}

	// enable the log?
	if (args.hasSwitch("log")) { Log::get().setEnabled(true); }

	// load and show settings
	module.cfg = Configuration(args);
	module.cfg.showSettings();

	// insert passwords
	module.keys.askForPasswords(module.cfg);

	// configure the path-name encryption/decryption/translation
	{
		const Key k = module.keys.getFileNameKey();
		std::shared_ptr<Cipher> cipher(module.cfg.getCipherFileNames(k.data, k.len));

		const char* absEncPath = realpath(args[args.size()-2].c_str(), nullptr);
		if (!absEncPath) {throw Exception("mount path not found!");}

		module.fp = new FilePath( absEncPath, cipher ) ;

	}

	// switch the process owner?
	if (args.hasOption("uid")) {
		const std::string username = args.getOption("uid");
		addLog("main", "switching process owner to " + username);
		uid_t uid = getUID(username.c_str());
		setuid(uid);
	}

	// construct FUSE arguments
	CMDLine fuseArgs;
	std::string fuseOpts = "big_writes";
	fuseArgs.add(args[0]);												// binary name
	fuseArgs.add("-s");													// single-threaded
	if (args.hasSwitch("foreground"))	{fuseArgs.add("-f");}			// run in foreground?
	if (args.hasSwitch("allow-other"))	{fuseOpts += ",allow_other";}	// allow other users
	fuseArgs.add("-o");													// fuse options
	fuseArgs.add(fuseOpts);												// fuse options
	fuseArgs.add(args[args.size()-1]);									// mount-point

	// start
	return startFuse(fuseArgs);
	
}
