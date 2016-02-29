#include "Tests.h"

#ifdef WITH_TESTS

static constexpr int BLK_SIZE = 4096;

TEST(Benchmark, IVGen) {

	uint8_t setup[32];
	uint32_t setupLen = 16;

	std::vector<std::string> algos = {"sha1", "sha256", "md5"};

	for (const std::string& algo : algos) {

		std::shared_ptr<IVGenerator> gen(IVGeneratorFactory::getByName(algo, setup, setupLen));

		uint8_t iv[16];
		uint32_t ivLen = 16;

		auto start = std::chrono::high_resolution_clock::now();
		uint32_t count = 1024*512;
		for (uint32_t i = 0; i < count; ++i) {
			gen->getIV(i, iv, ivLen);
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto diff = std::chrono::duration<double>(end-start).count();
		std::cout << algo << ":\t" << count / diff << " iv/sec. " << count/diff*BLK_SIZE/1024.0f/1024.f << " MB/sec" << std::endl;

	}

}

void _testBenchmark(const std::string& name, Cipher* cipher) {

	uint8_t key[32];
	uint32_t keyLen = cipher->getKeyLength();

	uint8_t iv[16] __attribute__((aligned(4096)));
	uint32_t ivLen = cipher->getIVLength();

	uint8_t src[BLK_SIZE] __attribute__((aligned(4096)));
	uint8_t dst[BLK_SIZE]__attribute__((aligned(4096)));

	cipher->setKey(key, keyLen);

	auto start = std::chrono::high_resolution_clock::now();
	const uint32_t count = 1024*128;
	for (uint32_t i = 0; i < count; ++i) {
		cipher->encrypt(src, dst, BLK_SIZE, iv, ivLen);
	}
	auto end = std::chrono::high_resolution_clock::now();
	auto diff = std::chrono::duration<double>(end-start).count();
	std::cout << name << ":\t" << count / diff << " blocks/sec. " << count/diff*BLK_SIZE/1024.0f/1024.f << " MB/sec" << std::endl;

}

TEST(Benchmark, Ciphers) {

#ifdef WITH_KERNEL
	CipherCryptoAPI aes128a(CryptoAPICiphers::AES_CBC_128); _testBenchmark( "kernel_aes_cbc_128", &aes128a );
	CipherCryptoAPI aes256a(CryptoAPICiphers::AES_CBC_256); _testBenchmark( "kernel_aes_cbc_256", &aes256a );
#endif

#ifdef WITH_OPENSSL
	CipherOpenSSL aes128b(OpenSSLCiphers::AES_CBC_128); _testBenchmark( "openssl_aes_cbc_128", &aes128b );
	CipherOpenSSL aes256b(OpenSSLCiphers::AES_CBC_256); _testBenchmark( "openssl_aes_cbc_256", &aes256b );
#endif

}

void _testBenchmark(const std::string& name, Digest* digest) {

	uint8_t out[64];

	auto start = std::chrono::high_resolution_clock::now();
	const uint32_t count = 512000;
	for (uint32_t i = 0; i < count; ++i) {
		digest->hash((uint8_t*)"lorem ipsum", 11, out);
	}
	auto end = std::chrono::high_resolution_clock::now();
	auto diff = std::chrono::duration<double>(end-start).count();
	std::cout << name << ": " << count / diff << " blocks/sec." << std::endl;

}



TEST(Benchmark, Digests) {

#ifdef WITH_KERNEL
	DigestCryptoAPI md5a(CryptoAPIDigests::MD5); _testBenchmark( "kernel_md5", &md5a );
	DigestCryptoAPI sha256a(CryptoAPIDigests::SHA256); _testBenchmark( "kernel_sha256", &sha256a );
	DigestCryptoAPI sha512a(CryptoAPIDigests::SHA512); _testBenchmark( "kernel_sha512", &sha512a );
#endif

#ifdef WITH_OPENSSL
	DigestOpenSSL md5b(OpenSSLDigests::MD5); _testBenchmark( "openssl_md5", &md5b );
	DigestOpenSSL sha256b(OpenSSLDigests::SHA256); _testBenchmark( "openssl_sha256", &sha256b );
	DigestOpenSSL sha512b(OpenSSLDigests::SHA512); _testBenchmark( "openssl_sha512", &sha512b );
#endif

}

TEST(Benchmark, Container) {

	uint8_t key[32];
	uint32_t keyLen = 32;

	std::shared_ptr<IVGenerator> ivGen(IVGeneratorFactory::getByName("sha256", key, keyLen));
	std::shared_ptr<Cipher> cipher(CipherFactory::getByName("aes_cbc_256", key, keyLen));



	const uint8_t src[1024*64] = {};

	{
		std::shared_ptr<MemoryContainer> fc(new MemoryContainer());
		EncryptedContainer efc(fc, cipher, ivGen);
		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 1024*128; ++i) {
			int offset = (i % 1024) * 4096;
			efc.write(src, 4096, offset);
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto diff = std::chrono::duration<double>(end-start).count();
		std::cout << "  aligned 4k: " << 512/diff << " MB/sec" << std::endl;
	}

	{
		std::shared_ptr<MemoryContainer> fc(new MemoryContainer());
		EncryptedContainer efc(fc, cipher, ivGen);
		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 1024*128; ++i) {
			int offset = (i % 1024) * 4095;
			efc.write(src, 4096, offset);
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto diff = std::chrono::duration<double>(end-start).count();
		std::cout << "unaligned 4k: " << 512/diff << " MB/sec" << std::endl;
	}

	{
		std::shared_ptr<MemoryContainer> fc(new MemoryContainer());
		EncryptedContainer efc(fc, cipher, ivGen);
		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 1024*16; ++i) {
			int offset = (i % 256) * 65536;
			efc.write(src, 65536, offset);
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto diff = std::chrono::duration<double>(end-start).count();
		std::cout << "  aligned 64k: " << 1024/diff << " MB/sec" << std::endl;
	}

	{
		std::shared_ptr<MemoryContainer> fc(new MemoryContainer());
		EncryptedContainer efc(fc, cipher, ivGen);
		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 1024*16; ++i) {
			int offset = (i % 256) * 65533;
			efc.write(src, 65536, offset);
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto diff = std::chrono::duration<double>(end-start).count();
		std::cout << "unaligned 64k: " << 1024/diff << " MB/sec" << std::endl;
	}

}

#endif
