#include "Tests.h"

#ifdef WITH_TESTS

TEST(FileContainer, HeaderSize) {
	ASSERT_EQ(4096, sizeof(EncryptedContainerHeader));
}

TEST(FileContainer, HeaderUpdate) {

	unlink(TMP_FILE_1);

	{
		EncryptedContainer ec(new FileContainer(TMP_FILE_1), nullptr, nullptr);
		ASSERT_EQ(0, ec.getSize());
		ec.setSize(1337);
		ASSERT_EQ(1337, ec.getSize());
	}
	
	{
		EncryptedContainer ec(new FileContainer(TMP_FILE_1), nullptr, nullptr);
		ASSERT_EQ(1337, ec.getSize());
	}
	
	unlink(TMP_FILE_1);

}

#endif
