#ifndef MEMORY_CONTAINER_H
#define MEMORY_CONTAINER_H

#include "Container.h"

#include <vector>

/**
 * store data in memory.
 * mainly used for testing
 */
class MemoryContainer : public Container {

private:

	std::vector<uint8_t> data;

public:


	/** write data into this container */
	virtual ssize_t write(const uint8_t* src, const size_t size, const off_t offset) override {

		if (data.size() < (offset+size)) {data.resize(offset+size);}
		memcpy(data.data()+offset, src, size);
		return size;

	}

	/** read data from this container */
	virtual ssize_t read(uint8_t* dst, const size_t size, const off_t offset) override {

		const ssize_t avail = data.size() - offset;
		const ssize_t read = std::min(avail, (ssize_t)size);
		if (read > 0) {
			memcpy(dst, data.data()+offset, read);
		}
		return read;

	}

	/** nothing to-do here */
	virtual int sync(const int datasync) override {
		(void) datasync;
		return 0;
	}

};

#endif // MEMORY_CONTAINER_H
