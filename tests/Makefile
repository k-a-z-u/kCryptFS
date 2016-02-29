CXX			= /usr/bin/g++
CXXFLAGS	= -Wall -O2 -march=native -std=c++11 -fstack-protector
LDFLAGS		= -lgtest -lpthread -lscrypt

# output binray
BIN			= tests

# all object-files to generate
OBJ			= $(addsuffix .o, $(basename $(wildcard *.cpp))) 

# build all test-cases
all: $(OBJ) 
	$(CXX) $(LDFLAGS) -o $(BIN) $(OBJ) 

# cleanup
clean:
	rm -rf $(BIN) $(OBJ)
	
# how to compile all .cpp files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<
