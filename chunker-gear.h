#ifndef CHUNKER_GEAR_H_H
#define CHUNKER_GEAR_H_H

#define doGear(hash, cbytes) {\
					hash = _mm512_slli_epi32(hash, 1);\
					__m512i idx = _mm512_and_epi32(cbytes, cmask);\
					cbytes = _mm512_srli_epi32(cbytes, 8);\
					__m512i tentry = _mm512_i32gather_epi32(idx, crct, 4);\
					hash = _mm512_add_epi32(hash,tentry);\
					hash = _mm512_and_epi32(hash,mm_break_mark);}





static inline uint32_t GEAR_HASHLEN(sscdc_args& args) { return args.break_mask_bit;}

static inline void doGear_serial(uint8_t c, uint32_t* x) {
	*x = (*x<<1) + crct[c];
}

void chunking_phase_one_serial_gear(sscdc_args& args, file_struct& fs){
	uint64_t offset = 0;

	uint64_t n_bytes_left = fs.test_length;
	if(fs.length <= GEAR_HASHLEN(args) || n_bytes_left <= args.min_chunksize) {
		printf(std::format("Serial: For file with {} bytes, no chunking\n", fs.length).c_str());
		// set remaining bitmap to 0000...1
		return;
	}

	uint32_t hash = 0;
	uint8_t *str = static_cast<uint8_t*>(fs.map);

	if (!args.skip_mini){
		while( offset < fs.test_length ){
			doGear_serial(str[offset], &hash);
			if(offset < GEAR_HASHLEN(args)){
				offset++;
				continue;
			}
			if((hash & args.break_mask) == args.magic_number){
					uint8_t b = fs.breakpoint_bm_serial[offset/8];
					b |= 1<<offset%8;
					fs.breakpoint_bm_serial[offset/8] = b;
					//printf("Serial: offset %d hash %x\n", offset, hash);
			}
			offset++;
		}
	}
	else {
		uint64_t last_offset = 0;
		uint64_t local_offset = 0;
		while( offset < fs.test_length ){
			doGear_serial(str[offset], &hash);
			if(local_offset < GEAR_HASHLEN(args)){
				offset++;
				local_offset++;
				continue;
			}
			if((hash & args.break_mask) == args.magic_number && offset - last_offset >= args.min_chunksize){
				uint8_t b = fs.breakpoint_bm_serial[offset/8];
				b |= 1<<offset%8;
				fs.breakpoint_bm_serial[offset/8] = b;
				last_offset = offset;
				offset -= GEAR_HASHLEN(args);
				local_offset = 0;
			}else
				offset++;
		}
	}
}


void chunking_phase_one_parallel_gear(sscdc_args& args, file_struct& fs){
	__m512i vindex = _mm512_setr_epi32(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
	__m512i mm_break_mark = _mm512_set1_epi32(args.break_mask);
	__m512i cmask = _mm512_set1_epi32(0xff);
	uint64_t offset = 0;
	uint64_t cur_segsize = 0;
	uint64_t last_segsize = 0;

	//uint32_t n_bytes_left = args.segment_size * N_LANES;
	uint32_t n_bytes_left = fs.test_length;
	uint32_t bytes_per_thread, bytes_last_thread;
	bytes_per_thread = (n_bytes_left/N_LANES)/32u*32u;
	bytes_last_thread = n_bytes_left - bytes_per_thread*(N_LANES - 1);
	//printf("Parallel: %u bytes %u bytes\n", bytes_per_thread, bytes_last_thread);
	vindex = _mm512_mullo_epi32(vindex, _mm512_set1_epi32(bytes_per_thread));

	uint64_t i = 0;
	uint64_t j = 0;
	__m512i hash = _mm512_set1_epi32(0);
	while (n_bytes_left > 0) {
		if (n_bytes_left >= N_LANES*args.segment_size) {
			cur_segsize = last_segsize = args.segment_size;
			n_bytes_left -= N_LANES*args.segment_size;
		}
		else {
			if (n_bytes_left <= N_LANES * GEAR_HASHLEN(args) || n_bytes_left <= args.min_chunksize){
				printf("Parallel: For file with %u bytes, no chunking %u %u\n", n_bytes_left, N_LANES*GEAR_HASHLEN(args), args.min_chunksize);
				// set remaining bitmap to 0000...1
				return;
			}

			cur_segsize = n_bytes_left/N_LANES/32*32;
			last_segsize = n_bytes_left-cur_segsize*(N_LANES-1);
			n_bytes_left = 0;
		}

		//printf("Processing data stream at [0X%x-0X%x-1]: 0x%x bytes/thread parallel\n", offset, offset+cur_segsize*N_LANES, cur_segsize);
		__m512i mm_bm = _mm512_set1_epi32(0);
		__m512i bm;

		//printf("LOOP: i %u j %u i32 %u\n", i,j, i%32);
		while(i < offset + cur_segsize + ((GEAR_HASHLEN(args) + 7) / 8 * 8)) {
			__m512i cbytes = _mm512_i32gather_epi32(vindex, static_cast<uint8_t*>(fs.map)+i, 1);

			for (j=0; j<sizeof(uint32_t); j++) {
				doGear(hash, cbytes);
				if (i+j < GEAR_HASHLEN(args))
					continue;

				//__m512i ret = _mm512_and_epi32(hash, mm_break_mark);
				__mmask16 bits = _mm512_cmpeq_epi32_mask(hash, _mm512_set1_epi32(args.magic_number));
				if(bits > 0) {
					__m512i ret = _mm512_maskz_set1_epi32(bits, 1);
					ret = _mm512_slli_epi32(ret, (i&31)+j);
					mm_bm = _mm512_or_epi32(mm_bm, ret);

					//for (uint8_t k=0; k<N_LANES; k++)
						//if(vector_idx(hash, k) == magic_number)
							//printf("parallel: offset %u hash %x\n", offset+i+k*cur_segsize+j, vector_idx(hash, k));
				}
			}

			if (((i % 32) == 28 || i+4 >= offset+cur_segsize+GEAR_HASHLEN(args)) && _mm512_cmpneq_epi32_mask(mm_bm,_mm512_set1_epi32(0)) > 0){
				bm = _mm512_i32gather_epi32(_mm512_srli_epi32(vindex, 3), fs.breakpoint_bm_parallel+(i>>5<<2), 1);
				bm = _mm512_or_epi32(mm_bm, bm);
				_mm512_i32scatter_epi32(fs.breakpoint_bm_parallel+(i>>5<<2), _mm512_srli_epi32(vindex, 3), bm, 1);
				mm_bm = _mm512_set1_epi32(0);
			}
			i += 4;
		}


		if(cur_segsize < last_segsize){
			uint8_t* str = static_cast<uint8_t*>(fs.map) + static_cast<uint64_t>(bytes_per_thread * (N_LANES - 1));
			uint32_t hash2 = vector_idx(hash, N_LANES - 1);
			//printf("Processing data stream at [0x%x-0x%lx]: sequential\n", offset+cur_segsize*N_LANES, fs.test_length-1);
			//sequential process of the remaining bytes
			while(i < last_segsize){
				doGear_serial(str[i], &hash2);
				if((hash2 & args.break_mask) == args.magic_number){
					uint8_t b = fs.breakpoint_bm_parallel[(i+bytes_per_thread* (N_LANES - 1))/8];
					b |= 1<<(i+bytes_per_thread* (N_LANES - 1))%8;
					fs.breakpoint_bm_parallel[(i+ (N_LANES - 1) *bytes_per_thread)/8] = b;
					//printf("Seq: i %d\n", i);
				}
				i++;
			}
			n_bytes_left = 0;
		}
		
		offset += cur_segsize;
	}

#if 0
	for (uint64_t k=0; k< fs.length; k+=8){
		uint8_t b = fs.breakpoint_bm_parallel[k/8];
		if ( b > 0){
			uint8_t j=0; 
			while(b > 0){
				if(b&0x1)
					printf("parallel: offset %d\n", k+j);
				b = b >> 1;
				j++;
			}
		}
	}
#endif
}


#endif
