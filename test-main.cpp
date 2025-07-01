#include "common.h"

int main(int argc, char *argv[]){
	uint64_t start, end, ptime = 0;
	uint64_t start_s, end_s, stime = 0;
	char fname_ab[256];
	std::string fname{};

	if (!parse_args(argc, argv))
		return 0;

	if (dir){
		uint64_t n = 0;
		collect_files(dir);
		strcpy(fname_ab, dir);
		fname = next_file();
		while(!fname.empty() && n < num_files_test){
			fs.filename = fname_ab;
			if (!init_fs(fs))
				continue;

			run_chunking_with_timer();
			finalize_fs(fs);
			n++;
		}
		clear_files();
	}else {
			if(init_fs(fs)){
				run_chunking_with_timer();
				finalize_fs(fs);
			}
	}

	print_stats(std::format("hash {}", hash_name));
	return 0;
}
