#include "common.h"

int main(int argc, char *argv[]){
	uint64_t start, end, ptime = 0;
	uint64_t start_s, end_s, stime = 0;
	std::string fname{};
	file_struct fs{};

	sscdc_args args = parse_args(argc, argv);
	if (!args.parse_success) {
		printf("Couldn't parse arguments!");
		return 1;
	}

	if (!args.dir.empty()) {
		uint64_t n = 0;
		collect_files(args);
		fname = next_file();
		while(!fname.empty() && n < args.num_files_test){
			fs.filename = fname;
			if (!init_fs(args, fs)) {
				printf("Warning: Couldn't initialize file_struct for file %s during directory processing, skipping", fs.filename.c_str());
				continue;
			}

			run_chunking_with_timer(args, fs);
			finalize_fs(fs);
			n++;
			fname = next_file();
		}
		clear_files();
	}
	else {
		fs.filename = args.filename;
		if (init_fs(args, fs)) {
			run_chunking_with_timer(args, fs);
			finalize_fs(fs);
		}
		else {
			printf("Couldn't initialize file_struct for single file processing!");
			return 1;
		}
	}

	print_stats(args);
	return 0;
}
