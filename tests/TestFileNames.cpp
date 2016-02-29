#include "Tests.h"

#ifdef WITH_TESTS

TEST (FileNames, EnDeCryptFile) { 

	uint8_t key[32] = {};
	uint32_t keyLen = 32;
	
	std::shared_ptr<Cipher> cipher(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	FilePath fp("/", cipher);
	const std::string ori = "test_file.txt";
	const std::string enc = fp.encrypt(ori);
	const std::string dec = fp.decrypt(enc);
	
	ASSERT_EQ(ori, dec);	

}

TEST (FileNames, EnDeCryptPath) { 

	uint8_t key[32] = {};
	uint32_t keyLen = 32;
	
	std::shared_ptr<Cipher> cipher(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	FilePath fp("/", cipher);
	const std::string ori = "/path/to/files.txt";
	const std::string enc = fp.encryptRelativeFileName(ori.c_str());
	const std::string dec = fp.decryptRelativeFileName(enc.c_str());
	
	// en-decrypt ok?
	ASSERT_EQ(ori, dec);

	// check the encrypted parts (all have the same filename length)
	FilePathSplitter splt(enc);
	ASSERT_EQ(Settings::FILE_PATH_ML, splt.next().length());
	ASSERT_EQ(Settings::FILE_PATH_ML, splt.next().length());
	ASSERT_EQ(Settings::FILE_PATH_ML, splt.next().length());
	
}

TEST (FileNames, EnDeCryptDotFolders) { 

	uint8_t key[32] = {};
	uint32_t keyLen = 32;
	
	std::shared_ptr<Cipher> cipher(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	FilePath fp("/", cipher);
	ASSERT_EQ(".", fp.encrypt("."));				// ./ must not be encrypted
	ASSERT_EQ("..", fp.encrypt(".."));				// ../ must not be encrypted
	ASSERT_NE("...", fp.encrypt("..."));			// .../ MUST be encrypted
	
	ASSERT_EQ(".", fp.decrypt("."));				// ./ must not be decrypted
	ASSERT_EQ("..", fp.decrypt(".."));				// ../ must not be decrypted
	ASSERT_NE("...", fp.decrypt("..."));			// .../ MUST be decrypted
	
	const std::string src = "/path/../with/./subs";						// must also work within full-paths
	const std::string enc = fp.encryptRelativeFileName(src.c_str());
	const std::string dec = fp.decryptRelativeFileName(enc.c_str());
	ASSERT_EQ(src, dec);
	
	FilePathSplitter splt(enc);
	ASSERT_EQ(Settings::FILE_PATH_ML, splt.next().length());
	ASSERT_EQ(2, splt.next().length());				// the ..
	ASSERT_EQ(Settings::FILE_PATH_ML, splt.next().length());
	ASSERT_EQ(1, splt.next().length());				// the .
	ASSERT_EQ(Settings::FILE_PATH_ML, splt.next().length());
	
}

TEST (FileNames, RelAbsFileName) { 

	uint8_t key[32] = {};
	uint32_t keyLen = 32;
	
	std::shared_ptr<Cipher> cipher(CipherFactory::getByName("aes_cbc_256", key, keyLen));
	FilePath fp("/my/encrypted/path",cipher);
	ASSERT_EQ("/my/encrypted/path/test/123.txt", fp.getAbsolutePath("/test/123.txt"));

}

TEST (FileNames, SplitNormal) {
	
	std::string path = "/test/path/to/encrypted/file.txt";
	FilePathSplitter splt(path);
	ASSERT_TRUE(splt.hasNext());
	
	ASSERT_EQ("test", splt.next());			ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("path", splt.next());			ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("to", splt.next());			ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("encrypted", splt.next());	ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("file.txt", splt.next());		ASSERT_FALSE(splt.hasNext());
		
}

TEST (FileNames, SplitRoot) {
	
	std::string path = "/";
	FilePathSplitter splt(path);
	
	// ensure we are already done (not a signle subfolder)
	ASSERT_FALSE(splt.hasNext());
	
}

TEST (FileNames, SplitBeyondEnd) {
	
	std::string path = "/path/x.txt";
	FilePathSplitter splt(path);
	
	ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("path", splt.next());			ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("x.txt", splt.next());		ASSERT_FALSE(splt.hasNext());
	
	// trying to read another next() at the end
	ASSERT_THROW(splt.next(), std::exception);
	
}

TEST (FileNames, SplitAndChange) {
	
	// iterate over the given path and replace all subfolders with new names
	std::string path = "/test/path/to/encrypted/file.txt";
	FilePathSplitter splt(path);
	ASSERT_TRUE(splt.hasNext());
	
	ASSERT_EQ("test", splt.next());			splt.setCur("another");		ASSERT_EQ("another", splt.cur());		ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("path", splt.next());			splt.setCur("folder");		ASSERT_EQ("folder", splt.cur());		ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("to", splt.next());			splt.setCur("for");			ASSERT_EQ("for", splt.cur());			ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("encrypted", splt.next());	splt.setCur("secure");		ASSERT_EQ("secure", splt.cur());		ASSERT_TRUE(splt.hasNext());
	ASSERT_EQ("file.txt", splt.next());		splt.setCur("files.data");	ASSERT_EQ("files.data", splt.cur());	ASSERT_FALSE(splt.hasNext());
	
	// check the created path
	ASSERT_EQ("/another/folder/for/secure/files.data", splt.getPath());
	
}


#endif
