CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

# select build type
SET( CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE}" )

PROJECT(KCryptFStests)

IF(NOT CMAKE_BUILD_TYPE)
	MESSAGE(STATUS "No build type selected. Default to Debug")
	SET(CMAKE_BUILD_TYPE "Debug")
ENDIF()



INCLUDE_DIRECTORIES(
	../lib/libscrypt/
)


FILE(GLOB HEADERS
	./*.h
)

FILE(GLOB SOURCES
	./*.cpp
)


# system specific compiler flags
ADD_DEFINITIONS(

    -std=gnu++11

	-Wall
	-Werror=return-type
	-Wextra

	-g
	-O0

)

SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,now -Wl,-z,relro -Wl,-soname" )


find_library(LIB_SCRYPT scrypt
	HINTS ../lib/libscrypt/
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
	gtest
	pthread
	${LIB_SCRYPT}
)

SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})

