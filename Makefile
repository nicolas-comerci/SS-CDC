SRC=test-main.cpp
BIN=ss-cdc
Debug_Bin=ss-cdc.debug
all:
	g++ -std=c++20 -march=native -O3 -o $(BIN) $(SRC) -lssl -lcrypto
	g++ -std=c++20 -march=native -g -o $(Debug_Bin) $(SRC) -lssl -lcrypto
all-skylake:
	g++ -std=c++20 -march=skylake-avx512 -O3 -o $(BIN) $(SRC) -lssl -lcrypto
	g++ -std=c++20 -march=skylake-avx512 -g -o $(Debug_Bin) $(SRC) -lssl -lcrypto
clean:
	rm -f $(BIN) $(Debug_Bin)
