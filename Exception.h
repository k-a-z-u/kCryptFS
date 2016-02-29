#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <string>
#include <exception>
#include <errno.h>
#include <string.h>

/** basic exception handling */
class Exception : public std::exception {

public:
	Exception(const std::string& msg, const int _errno) : msg(msg + " [" + strerror(_errno) + "]") {;}
	Exception(const std::string& msg) : msg(msg) {;}
	Exception(const char* msg) : msg(msg) {;}

private:
	std::string msg;

public:
	const char* what() const throw() {return msg.c_str();}

};

#endif //EXCEPTION_H
