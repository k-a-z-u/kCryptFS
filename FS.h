#ifndef FS_H
#define FS_H

#include "Log.h"
#include "Keys.h"
#include "CMDLine.h"
#include "Configuration.h"

#include "cipher/CipherFactory.h"
#include "digest/DigestFactory.h"
#include "container/EncryptedContainer.h"
#include "files/FilePath.h"

#include <cassert>

#include <cstdlib>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/time.h>
#include <sys/file.h>
#include <pwd.h>


/** convert from fuse file handle to custom type */
#define TO_FUSE_FH(fileHandle)		(uint64_t)fileHandle

/** return either the (postive) result code or errno */
#define resOrErrno(res) ( (res < 0) ? (-errno) : (res))

/** return either 0 or errno */
#define nullOrErrno(res) ( (res < 0) ? (-errno) : (0))

/** prevent unused warnings */
#define unused(var) (void) var;


/** the fuse-module's state */
struct ModuleState {

	/** configuration (ciphers, digests, ..) */
	Configuration cfg;

	/** encryption/decryption keys */
	Keys keys;

	/** file-name encryption/decryption/translation */
	FilePath* fp;

} module;


/**
 * file-handles attached to fuse-handles.
 * this is were things get a little-bit messy...
 * the ctor takes the user-key, the configuration and the file-descriptor
 * and setups the cipher, iv-generator and encryption-container from it
 */
struct FileHandle {

	// handle to an opened file
	const int fd;

	// the container to use for accessing this file
	EncryptedContainer ec;

	FileHandle(const int fd, const int flags, const Key& k, const Configuration& cfg) :
		fd(fd),
		ec(
			std::shared_ptr<FileContainer>(new FileContainer(fd, flags)),
			std::shared_ptr<Cipher>(cfg.getCipherFileData(k.data, k.len)),
			std::shared_ptr<IVGenerator>(cfg.getIVGenerator(k.data, k.len))
		) {

	}

};

/**
 * get the real file size for the given encrypted file.
 * TODO: ugly and slow as hell.. workarounds?
 */
static size_t getContainerSize(const std::string& absPath) {
	const int fd = open(absPath.c_str(), O_RDONLY);
	EncryptedContainerHeader header;
	pread(fd, &header, sizeof(header), 0);
	close(fd);
	return header.fileSize;
}

/** get file/path attributes */
int kcrypt_getattr(const char* relativePath, struct stat* statbuf) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = lstat(absPath.c_str(), statbuf);

	if (res >= 0) {
		statbuf->st_size = getContainerSize(absPath);			// the decrypted size
	}

	addLogRes("getattr", relativePath, res);
	return resOrErrno(res);

}

/** get opened file/path attributes */
int kcrypt_fgetattr(const char* relativePath, struct stat* statbuf, struct fuse_file_info* fi) {

	FileHandle* fh = (FileHandle*) fi->fh;
	const int res = fstat(fh->fd, statbuf);
	statbuf->st_size = fh->ec.getSize();			// the decrypted size
	addLogRes("fgetattr", relativePath, res);
	return resOrErrno(res);

}

int kcrypt_fsync(const char* relativePath, int datasync, struct fuse_file_info* fi) {

	FileHandle* fh = (FileHandle*) fi->fh;
	int res = fh->ec.sync(datasync);
	addLogRes("fsync", relativePath, res);
	return resOrErrno(res);

}

/** ?? */
int kcrypt_access(const char* relativePath, int mask) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = access(absPath.c_str(), mask);
	addLogRes("access", relativePath, res);
	return resOrErrno(res);

}

/** open the given file */
int kcrypt_open(const char* relativePath, struct fuse_file_info* fi) {

	// ensure we always have write permissions (this prevents issues with samba)
	const int flags = (fi->flags & ~(0x3)) | O_RDWR;

	// open the encrypted file
	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int fd = open(absPath.c_str(), flags);
	addLogRes("open", relativePath, fd);

	// create a new FileHandle for this
	if (fd >= 0) {
		const Key k = module.keys.getFileDataKey();
		FileHandle* fh = new FileHandle(fd, flags, k, module.cfg);
		fi->fh = TO_FUSE_FH(fh);
	}

	// done
	return nullOrErrno(fd);

}

/** release a previously opened file */
int kcrypt_release(const char* relativePath, struct fuse_file_info* fi) {

	FileHandle* fh = (FileHandle*) fi->fh;		// order here is very important to prevent crashes
	const int fd = fh->fd;						// remember the file-descriptor
	delete fh;									// delete the handle, this will also flush the container!!
	const int res = close(fd);					// now that everything is flushed, close the handle
	addLogRes("release", relativePath, res);
	return resOrErrno(res);

}

/** read from the given, previously opened, file */
int kcrypt_read(const char* relativePath, char* dst, size_t size, off_t offset, struct fuse_file_info* fi) {

	(void) relativePath;
	FileHandle* fh = (FileHandle*) fi->fh;
	return fh->ec.read((uint8_t*) dst, size, offset);

}

/** write to the given, previously opened, file */
int kcrypt_write(const char* relativePath, const char* src, size_t size, off_t offset, struct fuse_file_info* fi) {

	(void) relativePath;
	FileHandle* fh = (FileHandle*) fi->fh;
	return fh->ec.write((uint8_t*) src, size, offset);

}



/** rename the given file */
int kcrypt_rename(const char* relativePath, const char* newRelativePath) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const std::string newAbsPath = module.fp->getAbsolutePathEnc(newRelativePath);
	const int res = rename(absPath.c_str(), newAbsPath.c_str());
	addLogRes("rename", std::string(relativePath) + " -> " + newRelativePath, res);
	return resOrErrno(res);

}

/** delete the given file */
int kcrypt_unlink(const char* relativePath) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = unlink(absPath.c_str());
	addLogRes("unlink", relativePath, res);
	return resOrErrno(res);

}

/** change the given file's permissions */
int kcrypt_chmod(const char* relativePath, mode_t mode) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = chmod(absPath.c_str(), mode);
	addLogRes("chmod", relativePath, res);
	return resOrErrno(res);

}

/** Change the owner and group of a file */
int kcrypt_chown(const char* relativePath, uid_t uid, gid_t gid) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = chown(absPath.c_str(), uid, gid);
	addLogRes("chown", relativePath, res);
	return resOrErrno(res);

}

/** change the given file's last access time*/
int kcrypt_utime(const char* relativePath, struct utimbuf* ubuf) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = utime(absPath.c_str(), ubuf);
	addLogRes("utime", relativePath, res);
	return resOrErrno(res);

}

/** change the given file's last access and last modification time */
int kcrypt_utimens(const char* relativePath, const struct timespec ts[2]) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	struct timeval tv[2];
	tv[0].tv_sec = ts[0].tv_sec; tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec; tv[1].tv_usec = ts[1].tv_nsec / 1000;
	const int res = utimes(absPath.c_str(), tv);
	addLogRes("utimens", relativePath, res);
	return resOrErrno(res);

}

/** lock/unlock the given file */
int kcrypt_lock(const char* relativePath, struct fuse_file_info* fi, int cmd, struct flock* locks) {

	unused(fi); unused(cmd); unused(locks);
	//EncryptedFileContainer* cf = (EncryptedFileContainer*) fi->fh;
	//const int res = ::flock(cf->getFD(), (int) locks->l_type);
	//addLogRes("lock", relativePath, res);
	//return resOrErrno(res);
	addLog("lock (TODO)", relativePath);
	return 0;

}

/** change the given file's size */
int kcrypt_truncate(const char* relativePath, off_t newsize) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	// TODO: better ways?
	newsize += 8192; // header and trailing blocks
	const int res = truncate(absPath.c_str(), newsize);
	addLogRes("truncate", std::string(relativePath) + " to " + std::to_string(newsize), res);
	return resOrErrno(res);
	return 0;

}




/** create a new directory */
int kcrypt_mkdir(const char* relativePath, mode_t mode) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = mkdir(absPath.c_str(), mode);
	addLogRes("mkdir", relativePath, res);
	return resOrErrno(res);

}

/** remove an existing directory */
int kcrypt_rmdir(const char* relativePath) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = rmdir(absPath.c_str());
	addLogRes("rmdir", relativePath, res);
	return resOrErrno(res);

}

int kcrypt_mknod(const char* relativePath, mode_t mode, dev_t dev) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = mknod(absPath.c_str(), mode, dev);
	addLogRes("mknod", relativePath, res);
	return resOrErrno(res);

}

/** newly create the given file */
int kcrypt_create(const char* relativePath, const mode_t _mode, struct fuse_file_info* fi) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);

	//const int mode = (_mode & ~(0x3)) | O_RDWR;
	//const int fd = creat(absPath.c_str(), mode);
	const int fd = open(absPath.c_str(), O_CREAT|O_RDWR, 0700);
	std::cout << "create:" << fd << std::endl;
	addLogRes("create", relativePath, fd);

	// create a new FileHandle for this newly created file
	if (fd >= 0) {
		const Key k = module.keys.getFileDataKey();
		FileHandle* fh = new FileHandle(fd, O_RDWR, k, module.cfg);
		fi->fh = TO_FUSE_FH(fh);
	}

	// done
	return nullOrErrno(fd);

}


/** open the given directory for reading its contents */
int kcrypt_opendir(const char* relativePath, struct fuse_file_info* fi) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);

	errno = 0;
	DIR* dp = opendir(absPath.c_str());
	addLogRes("opendir", relativePath, (ssize_t)dp);

	// create a handle for this folder
	if (dp != NULL) {fi->fh = TO_FUSE_FH( dp );}
	return nullOrErrno(dp);

}

/** list all contents of a previously opened directory */
int kcrypt_readdir(const char* relativePath, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi) {

	unused(offset);

	// get the handle for the previously opened dir
	DIR* dp = (DIR*) fi->fh;
	addLogRes("readdir", relativePath, (ssize_t)dp);

	// read the directory and check whether it exists
	struct dirent* de = readdir(dp);
	if (de == 0) { return 0; }

	// read and add all entries
	do {
		std::string dec = module.fp->decrypt(de->d_name);
		int res = filler(buf, dec.c_str(), NULL, 0);
		if (res != 0) {return -ENOMEM;}
	} while ((de = readdir(dp)) != NULL);

	return 0;

}

/** close the previously opened directory */
int kcrypt_releasedir(const char* relativePath, struct fuse_file_info *fi) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	DIR* dp = (DIR*) fi->fh;
	const int res = closedir(dp);
	addLogRes("releasedir", relativePath, res);
	return resOrErrno(res);

}


/** get filesystem stats */
int kcrypt_statfs(const char* relativePath, struct statvfs* statv) {

	const std::string absPath = module.fp->getAbsolutePathEnc(relativePath);
	const int res = statvfs(absPath.c_str(), statv);
	addLogRes("statfs", relativePath, res);
	return resOrErrno(res);

}


/** fuse-module is initialized. return user-data */
void* kcrypt_init(struct fuse_conn_info* conn) {
	unused(conn);
	addLog("init", "");
	return nullptr;
}

/** fuse-module is destroyed */
void kcrypt_destroy(void* userdata) {
	unused(userdata);
	addLog("destroy", "");
}







int kcrypt_poll(const char* relativePath, struct fuse_file_info* fi, struct fuse_pollhandle* ph, unsigned* reventsp) {
	unused(relativePath); unused(fi); unused(ph); unused(reventsp);
	addLog("poll", ""); return -1;
}

int kcrypt_ioctl(const char* relativePath, int cmd, void* arg, struct fuse_file_info* fi, unsigned int flags, void* data) {
	unused(relativePath); unused(cmd); unused(arg); unused(fi); unused(flags); unused(data);
	addLog("ioctl", ""); return -1;
}



int kcrypt_fsyncdir(const char* relativePath, int isdatasync, struct fuse_file_info* fi) {
	unused(relativePath); unused(isdatasync); unused(fi);
	addLog("fsyncdir", ""); return -1;
}


/** supported operations */
struct fuse_operations kcrypt_ops = {};

/** setup and start fuse */
int startFuse(const CMDLine& args) {

	// ugly, but this way it also works with c++
	kcrypt_ops.init = kcrypt_init;
	kcrypt_ops.destroy = kcrypt_destroy;

	kcrypt_ops.getattr = kcrypt_getattr;
	kcrypt_ops.fsync = kcrypt_fsync;
	kcrypt_ops.fgetattr = kcrypt_fgetattr;
	kcrypt_ops.access = kcrypt_access;

	kcrypt_ops.mkdir = kcrypt_mkdir;
	kcrypt_ops.rmdir = kcrypt_rmdir;
	kcrypt_ops.mknod = kcrypt_mknod;
	kcrypt_ops.create = kcrypt_create;

	kcrypt_ops.open = kcrypt_open;
	kcrypt_ops.release = kcrypt_release;

	kcrypt_ops.read = kcrypt_read;
	kcrypt_ops.write = kcrypt_write;

	kcrypt_ops.chown = kcrypt_chown;
	kcrypt_ops.chmod = kcrypt_chmod;
	kcrypt_ops.utime = kcrypt_utime;
	kcrypt_ops.utimens = kcrypt_utimens;
	kcrypt_ops.lock = kcrypt_lock;
	kcrypt_ops.truncate = kcrypt_truncate;
	kcrypt_ops.statfs = kcrypt_statfs;
	kcrypt_ops.rename = kcrypt_rename;
	kcrypt_ops.unlink = kcrypt_unlink;

	kcrypt_ops.opendir = kcrypt_opendir;
	kcrypt_ops.readdir = kcrypt_readdir;
	kcrypt_ops.releasedir = kcrypt_releasedir;

	kcrypt_ops.poll = kcrypt_poll;
	kcrypt_ops.ioctl = kcrypt_ioctl;
	kcrypt_ops.fsyncdir = kcrypt_fsyncdir;


	// turn over control to fuse
	addLog("main", "turn over control to fuse");
	addLog("main", "using arguments: " + args.asString());
	std::vector<char*> argv = args.getArgv();
	return fuse_main(args.size(), argv.data(), &kcrypt_ops, nullptr);

}

#endif // FS_H
