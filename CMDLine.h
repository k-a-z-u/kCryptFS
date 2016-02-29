#ifndef CMDLINE_H
#define CMDLINE_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>

/**
 * parse command-line arguments
 */
class CMDLine {

private:

	std::vector<std::string> all;
	std::unordered_set<std::string> switches;
	std::unordered_map<std::string, std::string> options;

public:

	/** ctor */
	CMDLine(const int argc, const char* argv[]) {
		parse(argc, argv);
	}

	/** empty ctor */
	CMDLine() {
		;
	}

	/** get the value for the given key: --abc=xyz */
	std::string getOption(const std::string& key) const {
		auto it = options.find(key);
		return (it == options.end()) ? ("") : (it->second);
	}

	/** is the given option set? */
	bool hasOption(const std::string& key) const {
		return options.find(key) != options.end();
	}

	/** is the given switch set? */
	bool hasSwitch(const std::string& sw) const {
		return switches.find(sw) != switches.end();
	}

	/** array index access */
	const std::string& operator[] (const int idx) const {
		return all[idx];
	}

	/** number of arguments */
	size_t size() const {
		return all.size();
	}

	/** add a custom argument */
	void add(const std::string& opt) {
		all.push_back(opt);
	}

	/** get as char** */
	std::vector<char*> getArgv() const {
		std::vector<char*> vec;
		for (const std::string& arg : all) {
			vec.push_back((char*) arg.c_str());
		}
		return vec;
	}

	/** get as one-line string */
	std::string asString() const {
		std::string str;
		for (const std::string& arg : all) {str += arg + " ";}
		return str;
	}

private:

	/** parse cmd-line */
	void parse(const int argc, const char* argv[]) {

		// process all arguments
		for (int i = 0; i < argc; ++i) {

			// the current argument
			const std::string arg = argv[i];
			all.push_back(arg);

			// skip the first one
			if (i == 0) {continue;}

			// find some markers
			const size_t posM = arg.find("-");
			const size_t posMM = arg.find("--");
			const size_t posEq = arg.find("=");

			// --key=value
			if (posMM == 0 && posEq != std::string::npos) {
				const std::string key = arg.substr(2, posEq-2);
				const std::string val = arg.substr(posEq+1);
				options[key] = val;
			}

			// -option
			if (posM == 0 && posMM == std::string::npos) {
				const std::string sw = arg.substr(1);
				switches.insert(sw);
			}

		}

	}



};

#endif // CMDLINE_H
