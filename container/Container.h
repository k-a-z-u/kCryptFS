#ifndef CONTAINER_H
#define CONTAINER_H

/**
 * interface for all containers
 */
class Container {

public:

	virtual ~Container() {;}

	/** write data into this container */
	virtual ssize_t write(const uint8_t* src, const size_t size, const off_t offset) = 0;

	/** read data from this container */
	virtual ssize_t read(uint8_t* dst, const size_t size, const off_t offset) = 0;

	/** synchronize with the filesystem */
	virtual int sync(const int datasync) = 0;

};

#endif // CONTAINER_H
