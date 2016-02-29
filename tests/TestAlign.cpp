#include "Tests.h"

#ifdef WITH_TESTS

TEST(Align, align1) {
	
	const off_t offset = 157939696;
	const size_t size = 131072;

	AlignedRegion reg(offset, size);
	
	ASSERT_EQ(157937664, reg.getStart());						// aligned downwards to 4096
	ASSERT_GE(reg.getStart() + reg.getSize(), offset+size);		// region  must be captured
	
}

TEST(Align, size) {

	const size_t size = 131072;

	for (int o = 0; o < 1024*32; ++o) {
		AlignedRegion reg(o, size);
		ASSERT_GE(reg.getStart() + reg.getSize(), o+size);
	}

}

TEST(Align, partialDecrypt) {

	// NOTE: to speed things up when writing data, we only decrypt those blocks, that are partially overwritten
	// this test-cases ensures that the number of to-be-decrypted blocks is correct based on the given
	// to-be-overwritten regions

	uint8_t key[32];
	uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> cipher(CipherFactory::getByName("aes_cbc_256", key, keyLen));

	// start and end perfectly aligned
	{
		AlignedRegion a1(0, 4096);
		ASSERT_EQ(0, a1.decryptForOverwrite(*cipher, *ivGen, 0, 4096));

		AlignedRegion a2(0, 16384);
		ASSERT_EQ(0, a2.decryptForOverwrite(*cipher, *ivGen, 0, 16384));
	}

	// start not aligned
	{
		AlignedRegion a1(0, 4096);
		ASSERT_EQ(1, a1.decryptForOverwrite(*cipher, *ivGen, 4095, 1));

		AlignedRegion a2(0, 16384);
		ASSERT_EQ(1, a2.decryptForOverwrite(*cipher, *ivGen, 1, 16384-1));
	}

	// end not aligned
	{
		AlignedRegion a1(0, 4096);
		ASSERT_EQ(1, a1.decryptForOverwrite(*cipher, *ivGen, 0, 4096-1));

		AlignedRegion a2(0, 4096);
		ASSERT_EQ(1, a2.decryptForOverwrite(*cipher, *ivGen, 0, 1));

		AlignedRegion a3(0, 16384);
		ASSERT_EQ(1, a3.decryptForOverwrite(*cipher, *ivGen, 0, 16384-1));
	}

	// start and end not aligned
	{
		AlignedRegion a1(0, 4096);
		ASSERT_EQ(1, a1.decryptForOverwrite(*cipher, *ivGen, 1, 4096-2));		// only one block at all, do not decrypt twice

		AlignedRegion a2(0, 16384);
		ASSERT_EQ(2, a2.decryptForOverwrite(*cipher, *ivGen, 1, 16384-2));

		AlignedRegion a3(0, 16384);
		ASSERT_EQ(2, a3.decryptForOverwrite(*cipher, *ivGen, 4095, 16384-4095*2));
	}

}


#endif
