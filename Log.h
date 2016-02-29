#ifndef LOG_H
#define LOG_H

#include <string>
#include <iostream>
#include <iomanip>

#include <string.h>
#include <errno.h>

#define addLog(comp, val)			Log::get().add(comp, val)
#define addLogRes(comp, val, res)	Log::get().add(comp, val, res)

/**
 * helper-class to log to std::cout
 */
class Log {

private:

	bool enabled;

public:

	static Log& get() {
		static Log inst;
		return inst;
	}

	void setEnabled(const bool enabled) {
		Log::enabled = enabled;
	}

	void add(const std::string& component, const std::string& val) {
		addComp(component);
		std::cout << val << std::endl;
	}

	void add(const std::string& component, const std::string& val, const ssize_t res) {
		const std::string resStr = (res >= 0) ? (green + "OK") : (red + strerror(errno));
		addComp(component);
		std::cout << val << " {" << resStr + reset << "}" << std::endl;
	}

	void addComp(const std::string& component) {
		std::cout << blue << '[' << std::setfill(' ') << std::setw(12) << component << "] " << reset;
	}

	const std::string red = "\033[31;1m";
	const std::string green = "\033[32;1m";
	const std::string blue = "\033[34;1m";
	const std::string reset = "\033[0m";

};

#endif // LOG_H
