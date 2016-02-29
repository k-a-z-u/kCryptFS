#ifndef FILE_PATH_SPLITTER_H
#define FILE_PATH_SPLITTER_H

#include <string>
#include "../Exception.h"

/**
 * helper class to split a long path
 *		e.g.: /path/to/my/files/notes.txt
 * into its subfolders/files
 *		e.g.: path		to	my		files	notes.txt
 * and thereby modify subfolder-names on the fly
 *		e.g.: folder	for	the		data	hello.txt
 */
class FilePathSplitter {
	
private:
	
	/** the iterator region */
	std::size_t curStart = 0;
	std::size_t curEnd = 0;

	/** copy of the path to split/update */
	std::string path;

public:
	
	/** ctor with path-name */
	FilePathSplitter(const std::string& path) : path(path) {
		;
	}
	
	/** get the next subfolder/file */
	std::string next() {

		// sanity check
		if (!hasNext()) {throw Exception("end-of-path reached!");}

		// skip leading "/"
		curStart = curEnd + 1;

		// proceed until the next "/"
		curEnd = path.find('/', curStart);

		// end-reached?
		if (curEnd == std::string::npos) {curEnd = path.length();}

		// done
		return cur();

	}

	/** another subfolder/file following? */
	bool hasNext() const {
		return curEnd < path.length() - 1;
	}
	
	/** get the current subfolder/file */
	std::string cur() const {
		return path.substr(curStart, curEnd-curStart);
	}
	
	/** replace the current part (=subfolder) with a new name */
	void setCur(const std::string& str) {
		const std::size_t len = curEnd-curStart;
		path.replace(curStart, len, str);			// replace
		curEnd += str.length() - len;				// update the current region pointer
	}
	
	/** get the complete path. after e.g. modifying it */
	const std::string& getPath() const {
		return path;
	}
	
};

#endif // FILE_PATH_SPLITTER_H
