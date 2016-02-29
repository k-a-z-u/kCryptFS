#include "Tests.h"

#ifdef WITH_TESTS

#include <vector>
#include <thread>

TEST(EncryptedFileContainer, Write) {
	
}

TEST(EncryptedFileContainer, Read) {
	
}

/** request more-than-available bytes */
TEST(EncryptedFileContainer, PartialAccess) {

	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	std::shared_ptr<MemoryContainer> fc(new MemoryContainer());

	EncryptedContainer efc(fc, aes, ivGen);

	uint8_t src[64*1024];
	uint8_t buf[64*1024];
	int read;

	// fill
	efc.write(src, 6400, 0);
	ASSERT_EQ(efc.getSize(), 6400);

	// request more-than-available and check
	read = efc.read(buf, 16384, 0);
	ASSERT_EQ(read, 6400);
	ASSERT_EQ(0, memcmp(&src[0], buf, read));

	read = efc.read(buf, 16384, 4096);
	ASSERT_EQ(read, 2304);
	ASSERT_EQ(0, memcmp(&src[4096], buf, read));

	read = efc.read(buf, 16384, 2000);
	ASSERT_EQ(read, 4400);
	ASSERT_EQ(0, memcmp(&src[2000], buf, read));

	read = efc.read(buf, 16384, 6398);
	ASSERT_EQ(read, 2);
	ASSERT_EQ(0, memcmp(&src[6398], buf, read));

	read = efc.read(buf, 1, 6398);
	ASSERT_EQ(read, 1);
	ASSERT_EQ(0, memcmp(&src[6398], buf, read));

	read = efc.read(buf, 16384, 6399);
	ASSERT_EQ(read, 1);
	ASSERT_EQ(0, memcmp(&src[6399], buf, read));

	read = efc.read(buf, 16384, 6400);
	ASSERT_EQ(read, 0);

	read = efc.read(buf, 16384, 6401);
	ASSERT_EQ(read, 0);

	read = efc.read(buf, 16384, 8192);
	ASSERT_EQ(read, 0);

	read = efc.read(buf, 16384, 9123);
	ASSERT_EQ(read, 0);

}

TEST(EncryptedFileContainer, EnDeCryptSmallChunks) {
	
	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	std::shared_ptr<MemoryContainer> fc(new MemoryContainer());

	EncryptedContainer efc(fc, aes, ivGen);

	const int testSize = 1024*512;
	uint8_t buf[4096];

	// create random data
	uint8_t* rnd = (uint8_t*) malloc(testSize);
	for (int i = 0; i < testSize; ++i) {rnd[i] = rand();}

	const int wb = 13;
	int written = 0;
	for (int i = 0; i < testSize-8192; i+=wb) {
		efc.write(&rnd[i], wb, i);
		written += wb;
	}

	const int rb = 17;
	for (int i = 0; i < testSize-8192-rb; i+=rb) {
		efc.read(&buf[0], rb, i);
		ASSERT_EQ(0, memcmp(&buf[0], &rnd[i], rb));
	}

	ASSERT_EQ(efc.getSize(), written);

	// cleanup
	free(rnd);

}

TEST(EncryptedFileContainer, EnDeCryptLargeChunks) {
	
	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	std::shared_ptr<MemoryContainer> fc(new MemoryContainer());

	EncryptedContainer efc(fc, aes, ivGen);

	const int testSize = 1024*512;
	uint8_t buf[4096];

	// create random data
	uint8_t* rnd = (uint8_t*) malloc(testSize);
	for (int i = 0; i < testSize; ++i) {rnd[i] = rand();}

	const int wb = 5111;
	int written = 0;
	for (int i = 0; i < testSize-8192; i+=wb) {
		efc.write(&rnd[i], wb, i);
		written += wb;
	}

	const int rb = 1337;
	for (int i = 0; i < testSize-8192-rb; i+=rb) {
		efc.read(&buf[0], rb, i);
		ASSERT_EQ(0, memcmp(&buf[0], &rnd[i], rb));
	}

	ASSERT_EQ(efc.getSize(), written);

	// cleanup
	free(rnd);

}

TEST(EncryptedFileContainer, EnDeCryptHugeChunks) {
	
	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	std::shared_ptr<MemoryContainer> fc(new MemoryContainer());

	EncryptedContainer efc(fc, aes, ivGen);

	const int testSize = 1024*1024*8;
	uint8_t buf[256*1024];

	// create random data
	uint8_t* rnd = (uint8_t*)malloc(testSize);
	//for (int i = 0; i < testSize; ++i) {rnd[i] = rand();}

	const int wb = 131072;
	int written = 0;
	for (int i = 0; i < testSize-8192; i+=wb) {
		efc.write(&rnd[i], wb, i);
		written += wb;
	}

	const int rb = 130944;
	for (int i = 0; i < testSize-8192-rb; i+=rb) {
		efc.read(&buf[0], rb, i);
		ASSERT_EQ(0, memcmp(&buf[0], &rnd[i], rb));
	}

	ASSERT_EQ(efc.getSize(), written);

	delete(rnd);
	
}

TEST(EncryptedFileContainer, EnDeCryptOverlapChunks) {
	
	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	std::shared_ptr<MemoryContainer> fc(new MemoryContainer());

	EncryptedContainer efc(fc, aes, ivGen);

	const int testSize = 1024*1024*8;
	uint8_t buf[256*1024];

	// create random data
	uint8_t* rnd = (uint8_t*) malloc(testSize);
	//for (int i = 0; i < testSize; ++i) {rnd[i] = rand();}

	const int wb = 67135;
	int written = 0;
	for (int i = 0; i < testSize-8192; i+=wb/6) {
		efc.write(&rnd[i], wb, i);
		written += wb;
	}

	const int rb = 87323;
	for (int i = 0; i < testSize-8192-rb; i+=rb/6) {
		efc.read(&buf[0], rb, i);
		ASSERT_EQ(0, memcmp(&buf[0], &rnd[i], rb));
	}

	// cleanup
	free(rnd);

}

TEST(EncryptedFileContainer, EnDeCryptIssue) {
	
	
	
	struct Request {
		off_t pos;
		size_t size;
		Request(const off_t pos, const size_t size) : pos(pos), size(size) {;}
	};
	
	// some real-world requests
	std::vector<Request> requests;
	requests.push_back(Request(0,		128688));
	requests.push_back(Request(128688,	131072));
	requests.push_back(Request(259760,	131072));
	
	// setup container
	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	unlink(TMP_FILE_1);
	const int flags = O_RDWR|O_CREAT;
	int fd = open(TMP_FILE_1, flags, 0700);
	
	{
		

		std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
		std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
		std::shared_ptr<FileContainer> fc(new FileContainer(fd, flags));

		EncryptedContainer efc(fc, aes, ivGen);
		
		// test-size and buffer
		const int testSize = 1024*1024;
		uint8_t buf[131072];

		// create random data
		uint8_t* rnd = (uint8_t*) malloc(testSize);
		//for (int i = 0; i < testSize; ++i) {rnd[i] = rand();}

		// write requests
		for (const Request& r : requests) {
			auto run = [&] () {efc.write(&rnd[r.pos], r.size, r.pos);};
			std::thread t(run);
			t.detach();
		}
		
		usleep(1000*333); 	// wait for threads to finish;

		// read
		const size_t end = requests.back().pos + requests.back().size;
		for (size_t i = 0; i < end-4096; i+=4096) {
			efc.read(&buf[0], 4096, i);
			//ASSERT_EQ(buf[0], rnd[i]);
			ASSERT_EQ(0, memcmp(&buf[0], &rnd[i], 4096));
		}
	
		// cleanup
		free(rnd);
	
	}
	
	// cleanup
	close(fd);

}


TEST(EncryptedFileContainer, EnDeCryptRandom) {

	const uint8_t key[32] = {};
	const uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> aes(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	std::shared_ptr<MemoryContainer> fc(new MemoryContainer());

	EncryptedContainer efc(fc, aes, ivGen);

	const int testSize = 1024*1024*4;
	const int CMP = 64*1024;
	uint8_t buf[CMP];

	const int MAX_CHUNK = 128*1024;

	// create random data

	uint8_t* rnd1 = (uint8_t*) malloc(testSize+MAX_CHUNK);
	uint8_t* rnd2 = (uint8_t*) malloc(testSize+MAX_CHUNK);

	// overwrite the whole test-size several times
	// using new random data for each complete overwrite
	for (int run = 0; run < 64; ++run) {

		int start = 0;
		uint8_t* rnd = rnd1;

		// write the whole random buffer to file using various chunk sizes
		while(start < testSize) {
			const int size = 2048 + rand() % (MAX_CHUNK-2048);	// random write size. at least 2048 bytes
			efc.write(&rnd[start], size, start);				// write
			start += size * 0.85f;								// use overlapping writes
		}

		// ensure the file's data is consistent
		for (size_t i = 0; i < testSize; i+=CMP) {
			efc.read(&buf[0], CMP, i);
			ASSERT_EQ(0, memcmp(&buf[0], &rnd[i], CMP));
		}

		// swap rnd1 and rnd2
		std::swap(rnd1, rnd2);

	}

	// cleanup
	free(rnd1);
	free(rnd2);


}

#endif
