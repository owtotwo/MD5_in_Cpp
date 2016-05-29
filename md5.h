/* 
 * A MD5-Encryption Library implemented in C++
 * Copyright (c) 2016 sysu_AT < owtotwo@163.com >
 * 
 * Using GNU Lesser General Public License (LGPL)
 * [ http://www.gnu.org/licenses/lgpl-3.0.en.html ] for License Text
 * [ https://en.wikipedia.org/wiki/MD5 ] for Algorithm Detials
 *
 * Note : make sure that use -std=c++11 compilation flag
 */

#ifndef __OWTOTWO_MD5_H
#define __OWTOTWO_MD5_H

#include <iomanip> // for setw, setfill
#include <fstream> // for ifstream
#include <sstream> // for ostringstream, istringstream
#include <cstring> // for memcpy, memset
#include <string> // for string
#include <stdint.h> // for uint32_t, uint64_t



class MD5 {

public:	
/* ======================  API  ====================== */

	static inline std::string md5(std::istream& is);
	static inline std::string md5_file(const std::string& filename);
	static inline std::string md5(const std::string& str);

/* =================================================== */

private:
// ---------------------------- Implementation Detials -------------------------------

// keep the process state for each update
struct MD5state {
	uint32_t state[4];
	uint64_t bit_count; // valid number of bits of buffer chunk
	unsigned char buffer[64]; // buffer chunk
};


template <typename T> static inline T left_rotate(T x, T n) { 
	return (x << n) | (x >> (8 * sizeof(T) - n)); 
}

// md5 transform for each 512-bit chunk of message
static void md5_chunk_deal(uint32_t state[4], unsigned char chunk[64]) {

	static const uint32_t s_table[64] = {
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 
	};

	static const uint32_t K_table[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	uint32_t A = state[0], B = state[1], C = state[2], D = state[3]; 

	// break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
	uint32_t M[16];
	memcpy(M, chunk, 64);

	uint32_t F, g; // temp value
	for (uint32_t i = 0; i < 64; i++) {
		if (i < 16) {
			F = (B & C) | (~B & D); // (B and C) or ((not B) and D)
			g = i;
		} else if (i < 32) {
			F = (D & B) | (~D & C); // (D and B) or ((not D) and C)
			g = (5 * i + 1) % 16;
		} else if (i < 48) {
			F = B ^ C ^ D; // B xor C xor D
			g = (3 * i + 5) % 16;
		} else if (i < 64) {
			F = C ^ (B | ~D); // C xor (B or (not D))
			g = (7 * i) % 16;
		} else { throw; }
		uint32_t tmp = D;
		D = C;
		C = B;
		B += left_rotate((A + F + K_table[i] + M[g]), s_table[i]);
		A = tmp;
	}

	//Add this chunk's hash to result so far:
	state[0] += A;
	state[1] += B;
	state[2] += C;
	state[3] += D;

	memset(M, 0, sizeof(M)); // for satefy
}


static void md5_update(MD5state& context, unsigned char *input, unsigned int input_size) {
	// input_size is in bytes.

	unsigned int buffer_index = (context.bit_count / 8) % 64;
	context.bit_count += (uint64_t)input_size * 8;


	unsigned int padding_size = 64 - buffer_index;

	/* Transform as many times as possible.*/

	unsigned int index = 0;

	if (input_size >= padding_size) {
		// make up the buffer to 64 bytes
		memcpy(&context.buffer[buffer_index], input, padding_size);
		// run it
		md5_chunk_deal(context.state, context.buffer);
		// reset to begin
		buffer_index = 0; 
	
		for (index = padding_size; index + 63 < input_size; index += 64) {
			md5_chunk_deal(context.state, &input[index]);
		}
	}

	/* Add the remaining part of input to Buffer */
	memcpy(&context.buffer[buffer_index], &input[index], input_size-index);
}


static void md5_end_deal(unsigned char digest[16], MD5state& context) {

	static unsigned char padding_buffer[64] = {0x80, 0x00};

	// save the bit size of total processed buffer before padding
	unsigned char bit_size[8];
	memcpy(bit_size, &context.bit_count, 8);

	// append "1" bit to message
	// append "0" bits until message length in bits ≡ 448 (mod 512)
	unsigned int remain_size = (context.bit_count / 8) % 64;
	unsigned int padding_size = 
		remain_size < 56 ? 56 - remain_size : 120 - remain_size;
	md5_update(context, padding_buffer, padding_size);

	// append bit length of message as 64-bit little-endian integer to message
	md5_update(context, bit_size, 8);

	memcpy(digest, context.state, 16);

	context = MD5state(); // clean-up for safety
}

}; // class MD5


// ========================= API Implementation ===============================

inline std::string MD5::md5(std::istream& is) {
	if (!is) throw "Stream Error";

	is.seekg(0, is.end);
	int length = is.tellg();
	is.seekg(0, is.beg);
	
	unsigned char * buffer = new unsigned char [length];

	is.read((char*)buffer, length);

	if (!is) throw "Fail to read all the content from stream";

	MD5state tmp = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}, 0, {0}};
	
	md5_update(tmp, buffer, length);

	unsigned char result[16];
	md5_end_deal(result, tmp);

	std::ostringstream ss;

	for (int i = 0; i < 16; i++) {
		ss << std::hex << std::setw(2) << std::setfill('0') << int(result[i]);
	}

	delete[] buffer;
	return ss.str();
}

inline std::string MD5::md5_file(const std::string& filename) {
	std::ifstream fin(filename.c_str(), std::ifstream::binary);
	if (!fin) throw "File Error";
	std::string result = md5(fin);
	fin.close();
	return result;
}

inline std::string MD5::md5(const std::string& str) {
	std::istringstream is(str);
	if (!is) throw "String Error";
	return md5(is);
}


#endif // __OWTOTWO_MD5_H
