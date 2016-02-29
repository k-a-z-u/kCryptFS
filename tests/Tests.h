#ifdef WITH_TESTS

#include <gtest/gtest.h>

#define TMP_FILE_1	"/tmp/kCryptFS.dat"

#include "../container/MemoryContainer.h"
#include "../container/EncryptedContainer.h"
#include "../files/FilePath.h"
#include "../Helper.h"
#include "../cipher/CipherFactory.h"
#include "../digest/DigestFactory.h"


#endif

#include "../Exception.h"

inline int runTests(int argc, char** argv) {
#ifdef WITH_TESTS
	::testing::GTEST_FLAG(filter) = "*KeyDerivation*";
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
#else
	(void) argc;
	(void) argv;
	throw Exception("not compiled with test cases!");
#endif
}
