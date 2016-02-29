#include "Tests.h"

#ifdef WITH_TESTS

TEST(IVGenerator, generate) {
	
	uint8_t key[32] = {};
	uint32_t keyLen = 32;
	
	std::shared_ptr<IVGenerator> g(IVGeneratorFactory::getByName("sha256", key, keyLen));

	uint8_t iv1[16];
	uint8_t iv2[16];
	uint32_t ivLen = 16;
	
	// generate two times the same
	g->getIV(0, iv1, ivLen);
	g->getIV(0, iv2, ivLen);
	ASSERT_EQ(0, memcmp(iv1, iv2, ivLen));
	
	// generate something different
	g->getIV(1, iv1, ivLen);
	g->getIV(0, iv2, ivLen);
	ASSERT_NE(0, memcmp(iv1, iv2, ivLen));
	
}

/** get avg difference between two IVs */
inline int getAvgDiff(const uint8_t* a, const uint8_t* b, const uint32_t len) {
	int sum = 0;
	for (uint32_t i = 0; i < len; ++i) { sum += std::abs((int)a[i]-(int)b[i]); }
	return sum/len;
}

TEST(IVGenerator, entropy) {

	uint8_t key[32] = {};
	uint32_t keyLen = 32;
	
	std::shared_ptr<IVGenerator> g(IVGeneratorFactory::getByName("sha256", key, keyLen));

	uint8_t iv1[16];
	uint8_t iv2[16];
	uint32_t ivLen = 16;
	int sum, cnt;
	
	// bytewise
	sum = 0; cnt = 0;
	for (int i = 0; i < 128*1024; ++i) {
		g->getIV(i+0, iv1, ivLen);
		g->getIV(i+1, iv2, ivLen);
		sum += getAvgDiff(iv1, iv2, ivLen); ++cnt;
		ASSERT_GE(getAvgDiff(iv1, iv2, ivLen), 25);
	}
	std::cout << "avg: " << sum/cnt << std::endl;

	// blockwise
	sum = 0; cnt = 0;
	for (int i = 0; i < 128*1024; ++i) {
		g->getIV((i+0)*4096, iv1, ivLen);
		g->getIV((i+1)*4096, iv2, ivLen);
		sum += getAvgDiff(iv1, iv2, ivLen); ++cnt;
		ASSERT_GE(getAvgDiff(iv1, iv2, ivLen), 28);
	}
	std::cout << "avg: " << sum/cnt << std::endl;

}

#endif
