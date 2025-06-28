SRC=test-main.cpp
XXHASH-SRC=xxhash.c
BIN=ss-cdc
Debug_Bin=ss-cdc_debug
all:
	g++ -std=c++20 -march=native -O3 -o $(BIN) $(SRC) $(XXHASH-SRC)
	g++ -std=c++20 -march=native -g -o $(Debug_Bin) $(SRC) $(XXHASH-SRC)
all-skylake:
	g++ -std=c++20 -march=skylake-avx512 -O3 -o $(BIN) $(SRC) $(XXHASH-SRC)
	g++ -std=c++20 -march=skylake-avx512 -g -o $(Debug_Bin) $(SRC) $(XXHASH-SRC)
clean:
	rm -f $(BIN) $(Debug_Bin)
