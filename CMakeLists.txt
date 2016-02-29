CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# select build type
SET( CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE}" )

PROJECT(kCryptFS)

IF(NOT CMAKE_BUILD_TYPE)
	MESSAGE(STATUS "No build type selected. Default to Debug")
	SET(CMAKE_BUILD_TYPE "Debug")
ENDIF()

find_library(LIB_SCRYPT scrypt
	HINTS ./lib/libscrypt
)


# compile test-cases as well? needs gtest
OPTION(WITH_TESTS "Build with test-cases" OFF)
MESSAGE(STATUS "Compiled with tests-cases (WITH_TESTS): ${WITH_TESTS}")
IF(WITH_TESTS)
	add_definitions(-DWITH_TESTS)
	SET(EXTRA_LIBS ${EXTRA_LIBS} gtest pthread)
ENDIF()

# compile with OpenSSL digests/ciphers?
OPTION(WITH_OPENSSL "Build with OpenSSL digests/ciphers/key-derivations" OFF)
IF(WITH_OPENSSL)
	add_definitions(-DWITH_OPENSSL)
	SET(EXTRA_LIBS ${EXTRA_LIBS} crypto)
ENDIF()

# compile with OpenSSL digests/ciphers?
OPTION(WITH_KERNEL "Build with in-kernel digests/ciphers" OFF)
IF(WITH_KERNEL)
	add_definitions(-DWITH_KERNEL)
ENDIF()

# compile with OpenSSL digests/ciphers?
OPTION(WITH_SCRYPT "Build with scrypt key-derivation" OFF)
IF(WITH_SCRYPT)
	add_definitions(-WITH_SCRYPT)
	SET(EXTRA_LIBS ${EXTRA_LIBS} ${LIB_SCRYPT})
ENDIF()

INCLUDE_DIRECTORIES(
	./lib/libscrypt
)


FILE(GLOB HEADERS
	./*.h
	./*/*.h
)

FILE(GLOB SOURCES
	./*.cpp
	./*/*.cpp
)

# system specific compiler flags
ADD_DEFINITIONS(

	-D_FILE_OFFSET_BITS=64
	-std=gnu++11

	-Wall
	-Werror=return-type
	-Wextra

	-g
	-O0
	-march=native

)






# build a binary file
ADD_EXECUTABLE(
	${PROJECT_NAME}
	${HEADERS}
	${SOURCES}
)

# needed external libraries
TARGET_LINK_LIBRARIES(
	${PROJECT_NAME}
	fuse
	${EXTRA_LIBS}
)

SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})

