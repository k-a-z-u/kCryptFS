#ifndef FILE_CONTAINER_H
#define FILE_CONTAINER_H

#include <fcntl.h>
#include <string>

#include "../Exception.h"
#include "Container.h"

#include <unistd.h>


class FileContainer : public Container {

protected:

	/** the file-descriptor to write to / read from */
	int fd;

	/** the file-flags (read, write, ..) */
	const int flags;
	
	/** whether to perform cleanups or not */
	bool closeOnExit;
	

public:

	/** create from an external file-descriptor. do NOT close the description on destruction */
	FileContainer(const int fd, const int flags) : fd(fd), flags(flags), closeOnExit(false) {
		;
	}

	/** create from file-name */
	FileContainer(const std::string& absFile) : fd(0), flags(O_RDWR | O_CREAT), closeOnExit(true)  {
		fd = open(absFile.c_str(), flags, S_IRWXU);
		if (fd < 0) {throw Exception("error while opening file " + absFile);}
	}
	
	/** dtor */
	~FileContainer() {
		if (closeOnExit) {close(fd); fd = 0;}
	}
	
	/** synchronize the file with the filesystem */
	int sync(const int datasync) {
		if (datasync) {
			return fdatasync(fd);
		} else {
			return fsync(fd);
		}
	}
	
		
protected:
	

	
	/** is the file opened read-only? */
	bool isReadOnly() const {
		const int _flags = flags & 0x3;	// check lowest 3 bits for O_RDONLY, O_WRONLY, O_RDWR
		return (_flags == O_RDONLY);
	}

	
	/** write into the file */
	ssize_t write(const uint8_t* src, const size_t size, const off_t offset) {

		// do not write if the file was opened read-only
		if (isReadOnly()) {return -1;}
		const ssize_t bytes = pwrite(fd, src, size, offset);
		//fsync(fd);
		return bytes;

	}
	
	/** read from the file */
	ssize_t read(uint8_t* dst, const size_t size, const off_t offset) {
		//fsync(fd);
		//errno = 0;
		const ssize_t bytes = pread(fd, dst, size, offset);
		//std::cout << "reading at " << offset << " returned: " << bytes << " flags were:" << flags << " err:" << strerror(errno) << " fd:" << fd << std::endl;
		return bytes;
	}

};

#endif //FILE_CONTAINER_H
