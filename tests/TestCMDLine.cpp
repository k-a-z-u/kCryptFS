#include "Tests.h"

#ifdef WITH_TESTS

#include "../CMDLine.h"


TEST(CMDLine, parse) {

	const char* argv[] = {
		"binary",
		"-f",
		"--foreground",
		"--key=val",
		"--anotherKey=anotherValue",
		"-abcXYZ",
		"/my/path/1",
		"/my/path/2"
	};

	CMDLine cmd(8, argv);
	ASSERT_EQ("val", cmd.getOption("key"));
	ASSERT_EQ("anotherValue", cmd.getOption("anotherKey"));
	ASSERT_EQ("", cmd.getOption("doesNotExist"));

	ASSERT_TRUE(cmd.hasSwitch("f"));
	ASSERT_TRUE(cmd.hasSwitch("abcXYZ"));

	ASSERT_EQ("/my/path/2", cmd[cmd.size()-1]);
	ASSERT_EQ("/my/path/1", cmd[cmd.size()-2]);


}


#endif
