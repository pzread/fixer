CXXFLAGS = -O2 -Wall -Wextra -std=c++11 -Wno-unused-result -Wno-unused-parameter

all:
	g++ ${CXXFLAGS} -o bin/scan src/scan.cpp -lcgcef
	g++ ${CXXFLAGS} -o bin/patch src/patch.cpp -lcgcef
