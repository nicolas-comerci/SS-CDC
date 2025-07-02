#ifndef COMMON_H_H
#define COMMON_H_H

#include <algorithm>
#include "cycle.h"
#include <cstdio>
#include <cstdint>
#ifndef _WIN32
#include <fcntl.h>
#include <sys/mman.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif
#include <cstring>
#include <immintrin.h>
#include <cassert>
#include <ctime>
#include <filesystem>
#include <format>
#include <iostream>
#include <unordered_set>
#include <vector>

#include "xxhash.h"

#define HASHLEN 256

#define USE_MEMALLOC 1

#ifdef _WIN32
static inline uint64_t time_nsec(void) {
	static LARGE_INTEGER freq;
	static BOOL initialized = QueryPerformanceFrequency(&freq);
	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);
	return counter.QuadPart * 1000000000ULL / freq.QuadPart;
}
#else
static inline uint64_t time_nsec(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}
#endif

static constexpr uint32_t N_LANES = 16;


//[left, right)
struct chunk_boundary{
	uint64_t left;
	uint64_t right;
};

#ifndef _MSC_VER
#define vector_idx(table, idx) \
	((__v16si)table)[idx]
#else
#define vector_idx(table, idx) \
	table.m512i_i32[idx]
#endif

 alignas(16) static const uint32_t crct[256] =
{
	0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
	0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
	0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
	0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
	0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
	0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
	0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
	0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
	0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
	0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
	0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
	0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
	0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
	0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
	0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
	0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
	0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
	0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
	0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
	0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
	0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
	0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
	0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
	0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
	0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
	0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
	0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
	0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
	0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
	0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
	0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
	0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D,
};

static const uint32_t crcu[256] =
{
	0x00000000,0xce3371cb,0x4717e5d7,0x8924941c,0x8e2fcbae,0x401cba65,0xc9382e79,0x070b5fb2,
	0xc72e911d,0x091de0d6,0x803974ca,0x4e0a0501,0x49015ab3,0x87322b78,0x0e16bf64,0xc025ceaf,
	0x552c247b,0x9b1f55b0,0x123bc1ac,0xdc08b067,0xdb03efd5,0x15309e1e,0x9c140a02,0x52277bc9,
	0x9202b566,0x5c31c4ad,0xd51550b1,0x1b26217a,0x1c2d7ec8,0xd21e0f03,0x5b3a9b1f,0x9509ead4,
	0xaa5848f6,0x646b393d,0xed4fad21,0x237cdcea,0x24778358,0xea44f293,0x6360668f,0xad531744,
	0x6d76d9eb,0xa345a820,0x2a613c3c,0xe4524df7,0xe3591245,0x2d6a638e,0xa44ef792,0x6a7d8659,
	0xff746c8d,0x31471d46,0xb863895a,0x7650f891,0x715ba723,0xbf68d6e8,0x364c42f4,0xf87f333f,
	0x385afd90,0xf6698c5b,0x7f4d1847,0xb17e698c,0xb675363e,0x784647f5,0xf162d3e9,0x3f51a222,
	0x8fc197ad,0x41f2e666,0xc8d6727a,0x06e503b1,0x01ee5c03,0xcfdd2dc8,0x46f9b9d4,0x88cac81f,
	0x48ef06b0,0x86dc777b,0x0ff8e367,0xc1cb92ac,0xc6c0cd1e,0x08f3bcd5,0x81d728c9,0x4fe45902,
	0xdaedb3d6,0x14dec21d,0x9dfa5601,0x53c927ca,0x54c27878,0x9af109b3,0x13d59daf,0xdde6ec64,
	0x1dc322cb,0xd3f05300,0x5ad4c71c,0x94e7b6d7,0x93ece965,0x5ddf98ae,0xd4fb0cb2,0x1ac87d79,
	0x2599df5b,0xebaaae90,0x628e3a8c,0xacbd4b47,0xabb614f5,0x6585653e,0xeca1f122,0x229280e9,
	0xe2b74e46,0x2c843f8d,0xa5a0ab91,0x6b93da5a,0x6c9885e8,0xa2abf423,0x2b8f603f,0xe5bc11f4,
	0x70b5fb20,0xbe868aeb,0x37a21ef7,0xf9916f3c,0xfe9a308e,0x30a94145,0xb98dd559,0x77bea492,
	0xb79b6a3d,0x79a81bf6,0xf08c8fea,0x3ebffe21,0x39b4a193,0xf787d058,0x7ea34444,0xb090358f,
	0xc4f2291b,0x0ac158d0,0x83e5cccc,0x4dd6bd07,0x4adde2b5,0x84ee937e,0x0dca0762,0xc3f976a9,
	0x03dcb806,0xcdefc9cd,0x44cb5dd1,0x8af82c1a,0x8df373a8,0x43c00263,0xcae4967f,0x04d7e7b4,
	0x91de0d60,0x5fed7cab,0xd6c9e8b7,0x18fa997c,0x1ff1c6ce,0xd1c2b705,0x58e62319,0x96d552d2,
	0x56f09c7d,0x98c3edb6,0x11e779aa,0xdfd40861,0xd8df57d3,0x16ec2618,0x9fc8b204,0x51fbc3cf,
	0x6eaa61ed,0xa0991026,0x29bd843a,0xe78ef5f1,0xe085aa43,0x2eb6db88,0xa7924f94,0x69a13e5f,
	0xa984f0f0,0x67b7813b,0xee931527,0x20a064ec,0x27ab3b5e,0xe9984a95,0x60bcde89,0xae8faf42,
	0x3b864596,0xf5b5345d,0x7c91a041,0xb2a2d18a,0xb5a98e38,0x7b9afff3,0xf2be6bef,0x3c8d1a24,
	0xfca8d48b,0x329ba540,0xbbbf315c,0x758c4097,0x72871f25,0xbcb46eee,0x3590faf2,0xfba38b39,
	0x4b33beb6,0x8500cf7d,0x0c245b61,0xc2172aaa,0xc51c7518,0x0b2f04d3,0x820b90cf,0x4c38e104,
	0x8c1d2fab,0x422e5e60,0xcb0aca7c,0x0539bbb7,0x0232e405,0xcc0195ce,0x452501d2,0x8b167019,
	0x1e1f9acd,0xd02ceb06,0x59087f1a,0x973b0ed1,0x90305163,0x5e0320a8,0xd727b4b4,0x1914c57f,
	0xd9310bd0,0x17027a1b,0x9e26ee07,0x50159fcc,0x571ec07e,0x992db1b5,0x100925a9,0xde3a5462,
	0xe16bf640,0x2f58878b,0xa67c1397,0x684f625c,0x6f443dee,0xa1774c25,0x2853d839,0xe660a9f2,
	0x2645675d,0xe8761696,0x6152828a,0xaf61f341,0xa86aacf3,0x6659dd38,0xef7d4924,0x214e38ef,
	0xb447d23b,0x7a74a3f0,0xf35037ec,0x3d634627,0x3a681995,0xf45b685e,0x7d7ffc42,0xb34c8d89,
	0x73694326,0xbd5a32ed,0x347ea6f1,0xfa4dd73a,0xfd468888,0x3375f943,0xba516d5f,0x74621c94,
};


struct file_struct{
	std::string filename{};
	uint64_t length = 0;
	uint64_t test_length = 0;
	std::FILE* fd = nullptr;
	void* map = nullptr;
	uint8_t* breakpoint_bm_parallel = nullptr;
	uint8_t* breakpoint_bm_serial = nullptr;
	uint64_t next_start = 0;  // next chunk start, used by next_chunk()
};

inline void* portable_aligned_alloc(std::size_t alignment, std::size_t size) {
#ifdef _WIN32
	return _aligned_malloc(size, alignment);
#elif defined(__APPLE__) || defined(__MACH__)
	// macOS: posix_memalign is safest
	void* ptr = nullptr;
	if (posix_memalign(&ptr, alignment, size) != 0) {
		return nullptr;
	}
	return ptr;
#else
	// Linux and others with C11 support
	return std::aligned_alloc(alignment, size);
#endif
}

inline void portable_aligned_free(void* ptr) {
#ifdef _WIN32
	_aligned_free(ptr);
#else
	std::free(ptr);
#endif
}


static void* map_file(file_struct& fs){
#ifndef _WIN32
	fs.fd = fdopen(open(fs.fname, O_LARGEFILE|O_NOATIME), "rb");
#else
	fs.fd = std::fopen(fs.filename.c_str(), "rb");
#endif
	if (fs.fd == nullptr) {
		printf("Bad file descriptor?!\n");
		return nullptr;
	}
#ifndef _WIN32
	std::fseek(fs.fd, 0, SEEK_END);
	fs.length = std::ftell(fs.fd);
#else
	_fseeki64(fs.fd, 0, SEEK_END);
	fs.length = _ftelli64(fs.fd);
#endif

	if (fs.test_length == 0 || fs.test_length > fs.length)
		fs.test_length = fs.length;
	printf("length: %llu test_length %llu\n", fs.length, fs.test_length);
		
#if USE_MEMALLOC || _WIN32
	printf("Allocating memory for file\n");
	fs.map = portable_aligned_alloc(64, (fs.length+63)/64*64+HASHLEN);
	if(fs.map == nullptr){
		printf("Bad alloc?!\n");
		return nullptr;
	}
	printf("Memory allocated, reading file\n");
	std::fseek(fs.fd, 0, SEEK_SET);
	uint64_t read_size = 0;
	while (read_size < fs.length) {
		const uint64_t to_read_size = std::min<uint64_t>(fs.length - read_size, std::numeric_limits<size_t>::max());
		const auto actually_read = std::fread(static_cast<uint8_t*>(fs.map) + read_size, 1, to_read_size, fs.fd);
		if (to_read_size != actually_read) {
			printf("Reading file failed\n");
			return nullptr;
		}
		read_size += to_read_size;
	}
	printf("Read, zeroing memory\n");
	std::memset(static_cast<uint8_t *>(fs.map) + fs.length, 0, HASHLEN);
	printf("Done\n");
#else
	void *tmp = mmap(NULL, fs.length + HASHLEN, PROT_READ, MAP_PRIVATE, fileno(fs.fd), 0);
	if (tmp == MAP_FAILED) {
		printf("Map Failed!\n");
		return nullptr;
	}
	printf("Map success!\n");
	fs.map = tmp;
#endif

	return fs.map;
}

static void unmap_file(file_struct& fs){
	if(fs.map != nullptr){
#if USE_MEMALLOC
		portable_aligned_free(fs.map);
#else
		munmap(fs.map, fs.length+HASHLEN);
#endif
	}
	if (fs.fd != nullptr)
		std::fclose(fs.fd);
}

struct sscdc_args {
	bool parse_success = false;
	bool skip_mini = false;
	bool consistent_check = false;
	bool force_segment = false;
	std::string dir{};
	std::string filename{};
	uint64_t num_files_test = 0;
	std::string hash_name{};
	uint32_t min_chunksize = 2 * 1024;
	uint32_t max_chunksize = 64 * 1024;
	uint64_t segment_size = 1 * 1024 * 1024;
	uint32_t magic_number = 0;
	uint32_t break_mask_bit = 14;
	uint32_t break_mask = (1u << break_mask_bit) - 1;
	uint64_t test_length = 0;
};

typedef void (*phase_one_func)(sscdc_args& args, file_struct& fs);
static phase_one_func chunk_f = nullptr;

void chunking_phase_one_serial_gear(sscdc_args& args, file_struct& fs);
void chunking_phase_one_parallel_gear(sscdc_args& args, file_struct& fs);
void chunking_phase_one_serial_crc(sscdc_args& args, file_struct& fs);
void chunking_phase_one_parallel_crc(sscdc_args& args, file_struct& fs);

static void print_valid_hash_funcs() {
	printf("Only Valid hash function as below accepted: ");
	printf("gear:s ; ");
	printf("gear:p ; ");
	printf("crc:s ; ");
	printf("crc:p \n");
}

static bool set_chunk_func(sscdc_args& args){
	if (args.hash_name == "gear:s") {
		chunk_f = chunking_phase_one_serial_gear;
		args.consistent_check = false;
	}
	else if (args.hash_name == "gear:p")
		chunk_f = chunking_phase_one_parallel_gear;
	else if (args.hash_name == "crc:s") {
		chunk_f = chunking_phase_one_serial_crc;
		args.consistent_check = false;
	}
	else if (args.hash_name == "crc:p")
		chunk_f = chunking_phase_one_parallel_crc;
	else{
		print_valid_hash_funcs();
		return false;
	}
	return true;
}


static inline void help(){
	printf("help: -f fname -m min -M max_chunksize_KB"
			"-ss segment_MB -ts test_size -nm magic_number -d dir -bmb num -H hash -cc -skip\n");
	print_valid_hash_funcs();
}

sscdc_args parse_args(int argc, char *argv[]){
	sscdc_args args{};
	for (int i = 1; i < argc; i++){
		if(strncmp(argv[i], "-f", 2) == 0){
			assert(i<argc-1);
			args.filename = argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-m", 2) == 0){
			assert(i<argc-1);
			args.min_chunksize = atoi(argv[i+1])*1024;
			i++;
		}else if(strncmp(argv[i], "-M", 2) == 0){
			assert(i<argc-1);
			args.max_chunksize = atoi(argv[i+1])*1024;
			i++;
		}else if(strncmp(argv[i], "-ss", 3) == 0){
			assert(i<argc-1);
			args.segment_size = atoi(argv[i+1])*1024*1024;
			i++;
		}else if(strncmp(argv[i], "-ts", 3) == 0){
			assert(i<argc-1);
			args.test_length = atoi(argv[i+1])*1024*1024;
			i++;
		}else if(strncmp(argv[i], "-nm", 3) == 0){
			assert(i<argc-1);
			args.magic_number = atoi(argv[i+1]);
			i++;
		}else if(strncmp(argv[i], "-N", 2) == 0){
			assert(i<argc-1);
			args.num_files_test = strtoull(argv[i+1], nullptr, 10);
			i++;
		}else if(strncmp(argv[i], "-bmb", 4) == 0){
			assert(i<argc-1);
			args.break_mask_bit = atoi(argv[i+1]);
			args.break_mask = (1u<<args.break_mask_bit)-1;
			i++;
		}else if(strncmp(argv[i], "-d", 2) == 0){
			assert(i<argc-1);
			args.dir = argv[i+1];
			i++;
		}else if(strncmp(argv[i], "-H", 2) == 0){
			assert(i<argc-1);
			args.hash_name = argv[i+1];
			i++;
		} else if(strncmp(argv[i], "-skip", 5) == 0){
			args.skip_mini = true;
		}else if (strncmp(argv[i], "-cc", 3) == 0){
			args.consistent_check = true;
		}else if (strncmp(argv[i], "-S", 2) == 0){
			args.force_segment = true;
		}else{
			help();
			return args;
		}
	}

	if (args.hash_name.empty()){
		args.hash_name = "crc:p";
	} 

	if (!set_chunk_func(args)) {
		return args;
	}

	//printf("INFO: hash %s\n", hash_name);
	if (args.filename.empty() && args.dir.empty()){
		help();
		return args;
	}

	args.parse_success = true;
	return args;
}


static void bitmap_consistency_test(sscdc_args& args, file_struct& fs) {
	uint32_t bp_count = 0;

	if(args.skip_mini) {
		//printf("Warning: consistent_check skipped because skip_mini enabled\n");
		args.consistent_check = false;
		return;
	}

	if(fs.breakpoint_bm_serial == nullptr || fs.breakpoint_bm_parallel == nullptr) {
		printf("Bitmap not allocated\n");
		return;
	}
	for(uint64_t i = 0; i < fs.test_length; i += 8) {
		if(fs.breakpoint_bm_parallel[i/8] != fs.breakpoint_bm_serial[i/8]) {
			printf(std::format("{}: Bitmap not consistent at offset {:x} ({:d}), total length {}\n", fs.filename, i+i%8, i+i%8, fs.test_length).c_str());
			return;
		}
		if (fs.breakpoint_bm_parallel[i/8] > 0) {
			bp_count++;
		}
	}

	//printf("Processing %s, %lu bytes and %u break points detected\n", fs.fname, fs.test_length, bp_count);
}

static inline uint64_t reach_end(const file_struct& fs){
	return fs.length <= fs.next_start;
}

static inline uint64_t bytes_left(const file_struct& fs){
	return fs.length - fs.next_start;
}

static inline bool is_breakpoint(const uint8_t* cutpoint_bitmap, uint64_t idx){
	uint8_t b = cutpoint_bitmap[idx/8];
	return ((b>>(idx%8)) & 0x1) == 1;
}


static void next_chunk_parallel(sscdc_args& args, file_struct& fs, uint64_t& current_chunk_size, const uint8_t* cutpoint_bitmask) {
	__m512i vindex = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	__m512i zero_v = _mm512_set1_epi32(32);
	for (current_chunk_size = args.min_chunksize; current_chunk_size < args.max_chunksize && fs.next_start + current_chunk_size < fs.length; ) {
		uint64_t offset = (fs.next_start + current_chunk_size) % 8;
		if (offset > 0) {
			uint8_t b = cutpoint_bitmask[(fs.next_start + current_chunk_size) / 8];
			b = b >> offset;
			if (b) {
				while ((b & 0x1) == 0) {
					current_chunk_size++;
					b = b >> 1;
				}
				//printf("start %lu offset %d idx2: %lu\n", fs.next_start, offset, fs.next_start + current_chunk_size);
				//printf("idx: %lu\n", fs.next_start + current_chunk_size);
				break;
			}
			else
				current_chunk_size += 8 - offset;
		}
		__m512i bm = _mm512_i32gather_epi32(vindex, &cutpoint_bitmask[(fs.next_start + current_chunk_size) / 8], 4);
		__m512i bit = _mm512_lzcnt_epi32(bm);
		__mmask16 lane_has_result_bitmask = _mm512_cmpneq_epi32_mask(bit, zero_v);
		if (lane_has_result_bitmask == 0) {
			current_chunk_size += 512ull;
			//printf("lane_has_result_bitmask: %x bit[0] %x idx %lu\n", lane_has_result_bitmask, vector_idx(bm, 0), fs.next_start + current_chunk_size);
			continue;
		}
		uint8_t lane_i = 0;
		while (((lane_has_result_bitmask >> lane_i) & 0x1) == 0) {
			lane_i++;
		}
		int32_t lane_bitmap = vector_idx(bm, lane_i);
		current_chunk_size += 32ull * lane_i;
		//printf("lane_has_result_bitmask: %x bm[s] %x idx %lu s %d %d ", lane_has_result_bitmask, vector_idx(bm, s), fs.next_start + current_chunk_size, s, vector_idx(vindex*32,2));
		uint8_t bit_i = 0;
		while (((lane_bitmap >> bit_i) & 0x1) == 0)
			bit_i++;
		current_chunk_size += bit_i;
		if (args.force_segment) {
			if ((fs.next_start + current_chunk_size) % args.segment_size < fs.next_start % args.segment_size) {
				current_chunk_size -= (fs.next_start + current_chunk_size) % args.segment_size;
				//printf("idx: %lu\n", fs.next_start + current_chunk_size);
				break;
			}
		}
		//printf("lane_bitmap %x idx: %lu\n", lane_bitmap, fs.next_start + current_chunk_size);
		//printf("idx: %lu\n", fs.next_start + current_chunk_size);
		break;
	}
}


static bool next_chunk(sscdc_args& args, file_struct& fs, chunk_boundary& cb, bool use_parallel, const uint8_t* cutpoint_bitmask = nullptr){
	uint64_t current_chunk_size = 0;
	if (!cutpoint_bitmask) cutpoint_bitmask = use_parallel ? fs.breakpoint_bm_parallel : fs.breakpoint_bm_serial;

	assert(cb);
	if (reach_end(fs))
		return false;
	if (bytes_left(fs) < 2ull * args.min_chunksize) {
		cb.left = fs.next_start;
		cb.right = fs.length;
		fs.next_start = cb.right;
		return true;
	}

	if(args.force_segment && args.segment_size - fs.next_start%args.segment_size < 2ull * args.min_chunksize) {
		cb.left = fs.next_start;
		cb.right = fs.next_start + args.segment_size - fs.next_start%args.segment_size;
		fs.next_start = cb.right;
		return true;
	}

	if (use_parallel) {
		next_chunk_parallel(args, fs, current_chunk_size, cutpoint_bitmask);
	}
	else {
		for (current_chunk_size = args.min_chunksize; current_chunk_size < args.max_chunksize && fs.next_start + current_chunk_size < fs.length; ) {
			if (is_breakpoint(cutpoint_bitmask, fs.next_start + current_chunk_size)) {
				//printf("idx: %lu\n", fs.next_start + current_chunk_size);
				break;
			}
			current_chunk_size++;
		}
	}

	cb.left = fs.next_start;
	cb.right = fs.next_start + current_chunk_size + 1;
	fs.next_start = cb.right;
	return true;
}

static void cut_chunks(sscdc_args& args, file_struct& fs, const uint8_t* cutpoint_bitmap, bool use_parallel) {
	chunk_boundary cb;
	fs.next_start = 0;
	while (next_chunk(args, fs, cb, use_parallel, cutpoint_bitmap)) {}
	fs.next_start = 0;
}

static inline void print_fingerprint(uint8_t *hash, uint64_t len){
	for(uint64_t i = 0; i < len; i++){
		printf("%x", hash[i]);
	}
	printf("\n");
}


struct dedup_stats_st{
	uint64_t total_size;
	uint64_t total_chunks;
	uint64_t uniq_chunks;
	uint64_t uniq_size;
	uint64_t avx_ns;
	uint64_t serial_ns;
	uint64_t break_ns;
	uint64_t break_serial_ns;
	uint64_t dedup_ns;

	double avx_cycles;
	double serial_cycles; 
};
	
static struct dedup_stats_st dedup_stats={.total_size = 0, .total_chunks = 0, .uniq_chunks = 0, .uniq_size = 0,
	.avx_ns = 0, .serial_ns = 0, .break_ns = 0, .break_serial_ns = 0, .dedup_ns = 0, .avx_cycles = 0.0,
	.serial_cycles = 0.0};

static void print_stats(sscdc_args& args) {
	printf(std::format(
		"Output: mini_chunksize {} max_chunksize {} expect_avg_chunksize {} magic_number {} seg_size {}",
		args.min_chunksize, args.max_chunksize, 1<<args.break_mask_bit, args.magic_number, args.segment_size).c_str()
	);
	if (!args.hash_name.empty()) {
		printf(" %s", std::format("hash {}", args.hash_name).c_str());
	}
	printf(std::format(
		" force_segment {} skip_mini {} unique_bytes {} total_bytes {} unique_chunks {} total_chunks {} dedup_ratio {:.2f} avg_chunk_size {:.2f}",
		args.force_segment, args.skip_mini, dedup_stats.uniq_size, dedup_stats.total_size, dedup_stats.uniq_chunks,
		dedup_stats.total_chunks, 1.0*dedup_stats.total_size/dedup_stats.uniq_size, dedup_stats.total_size/dedup_stats.total_chunks*1.0).c_str()
	);

	printf(std::format(" break_time {} break_serial_time {} speedup {:.2f} dedup_time {} chunk_time_parallel {} chunk_time_serial {}",
		dedup_stats.break_ns, dedup_stats.break_serial_ns,
		1.0 * dedup_stats.break_serial_ns / dedup_stats.break_ns,
		dedup_stats.dedup_ns,
		dedup_stats.avx_ns,
		dedup_stats.serial_ns
	).c_str());
	if(args.consistent_check)
		printf(std::format(
			" speedup {:.2f} chunk_cycles_parallel {:.2f}, chunk_cycles_serial {:.2f} chunk_cycles_speedup {:.2f} cycles_per_byte_parallel {:.2f} cycles_per_byte_serial {:.2f} \n", 
			1.0 * dedup_stats.serial_ns / dedup_stats.avx_ns, 
			dedup_stats.avx_cycles, dedup_stats.serial_cycles, 
			dedup_stats.serial_cycles / dedup_stats.avx_cycles, 
			dedup_stats.avx_cycles / dedup_stats.total_size, 
			dedup_stats.serial_cycles / dedup_stats.total_size
		).c_str());
	else{
		printf(" speedup --\n");
	}
}

static void chunking_phase_two(sscdc_args& args, file_struct& fs, bool use_parallel) {
	std::unordered_set<uint64_t> known_fingerprints{};
	struct chunk_boundary cb;
	uint64_t hash;
	uint64_t num_chunks = 0, uniq_chunks = 0;
	uint64_t s_time;
	const uint8_t* cutpoint_bitmap = use_parallel ? fs.breakpoint_bm_parallel : fs.breakpoint_bm_serial;

	s_time = time_nsec();
	//printf("cut time: %lu\n", dedup_stats.break_ns);
	cut_chunks(args, fs, cutpoint_bitmap, true);
	dedup_stats.break_ns += time_nsec() - s_time;
	//printf("cut time: %lu\n", dedup_stats.break_ns);

	fs.next_start = 0;
	s_time = time_nsec();
	cut_chunks(args, fs, cutpoint_bitmap, false);
	dedup_stats.break_serial_ns += time_nsec() - s_time;

	fs.next_start = 0;

	while(next_chunk(args, fs, cb, use_parallel)) {
		s_time = time_nsec();
		hash = XXH3_64bits(static_cast<uint8_t*>(fs.map) + cb.left, cb.right - cb.left);
		dedup_stats.dedup_ns += time_nsec() - s_time;
		dedup_stats.total_chunks++;
		dedup_stats.total_size += cb.right - cb.left;
		if(!known_fingerprints.contains(hash)){
			known_fingerprints.insert(hash);
			uniq_chunks++;
			dedup_stats.uniq_size+= cb.right-cb.left;
			dedup_stats.uniq_chunks ++;
		}
	}
}

static bool init_fs(sscdc_args& args, file_struct& fs) {
	printf("map_file starting\n");
	if (map_file(fs) == nullptr){
		printf("Error: map file %s failed\n", fs.filename.c_str());
		return false;
	}
	printf("map_file seems successful\n");

	fs.test_length = args.test_length ? std::min(args.test_length, fs.length) : fs.length;

	const auto bitmap_size = (fs.length+7)/8 + HASHLEN/8;
	fs.breakpoint_bm_parallel = static_cast<uint8_t*>(portable_aligned_alloc(64, bitmap_size));
	if(!fs.breakpoint_bm_parallel){
		printf("Error: allocate breakpoint bitmap failed, exit\n");
		return false;
	}
	std::memset(fs.breakpoint_bm_parallel, 0, bitmap_size);

	fs.breakpoint_bm_serial = static_cast<uint8_t*>(portable_aligned_alloc(64, bitmap_size));
	if(!fs.breakpoint_bm_serial){
		printf("Error: allocate breakpoint bitmap failed, exit\n");
		return false;
	}
	std::memset(fs.breakpoint_bm_serial, 0, bitmap_size);

	return true;
}


static void finalize_fs(file_struct& fs) {
	if(fs.breakpoint_bm_parallel)
		portable_aligned_free(fs.breakpoint_bm_parallel);
	if(fs.breakpoint_bm_serial)
		portable_aligned_free(fs.breakpoint_bm_serial);
	fs.test_length = fs.length = fs.next_start = 0;
	unmap_file(fs);
}


static uint64_t num_files = 0;
static std::vector<std::filesystem::directory_entry> files;

static bool filter(const std::filesystem::directory_entry& entry) {
	return entry.is_regular_file() && entry.path().filename() != ".";
}

static uint64_t collect_files(sscdc_args& args) {
	files.clear();
	try {
		for (const auto& entry : std::filesystem::directory_iterator(args.dir)) {
			if (filter(entry)) {
				files.push_back(entry);
			}
		}

		// Sort alphabetically by filename
		std::ranges::sort(files, [](const std::filesystem::directory_entry& a, const std::filesystem::directory_entry& b) {
			return a.path().filename() < b.path().filename();
		});

		num_files = files.size();
		if (args.num_files_test == 0) {
			args.num_files_test = num_files;
		}

		std::cout << "Info: total " << num_files << " files in " << args.dir
				  << ", " << args.num_files_test << " files to be tested\n";

		return num_files;

	} catch (const std::filesystem::filesystem_error& e) {
		std::cerr << "Filesystem error: " << e.what() << "\n";
		return 0;
	}
}

static std::string next_file(){
	if (num_files == 0) return "";
	return files[--num_files].path().string();
}

static void clear_files() {
	files.clear();
}


// below are chunk functions 
//
#include "chunker-crc.h"
#include "chunker-gear.h"

static void run_chunking_with_timer(sscdc_args& args, file_struct& fs){
	printf("Started run_chunking_with_timer\n");
	uint64_t start, end;
	uint64_t start_s, end_s;
	uint64_t start_ticks, end_ticks;
	uint64_t start_ticks_s, end_ticks_s;
	phase_one_func sfunc = nullptr;

	const bool use_parallel = args.hash_name.find(":p") != std::string::npos;
	if(use_parallel) {
			start = time_nsec();
			start_ticks = getticks();
			chunk_f(args, fs);
			end_ticks = getticks();
			end = time_nsec();
			dedup_stats.avx_ns += end-start;
			dedup_stats.avx_cycles += elapsed(end_ticks, start_ticks);

			if(args.consistent_check){
				if(args.hash_name.find("crc") != std::string::npos) {
					sfunc = chunking_phase_one_serial_crc;
				}
				else if(args.hash_name.find("gear") != std::string::npos) {
					sfunc = chunking_phase_one_serial_gear;
				}
				else
					assert(0);

				start_s = time_nsec();
				start_ticks_s = getticks();
				sfunc(args, fs);
				end_ticks_s = getticks();
				end_s = time_nsec();
				dedup_stats.serial_ns += end_s-start_s;
				dedup_stats.serial_cycles += elapsed(end_ticks_s, start_ticks_s);

				if (!args.skip_mini)
					bitmap_consistency_test(args, fs);
				else {
					//printf("Warning: consistent_check skipped because skip_mini enabled\n");
				}
			}
	}
	else {
			start = time_nsec();
			chunk_f(args, fs);
			end = time_nsec();
			dedup_stats.serial_ns += end - start;
			printf("Finished serial hashing! Onto phase 2\n");
	}
	chunking_phase_two(args, fs, use_parallel);
}

#endif
