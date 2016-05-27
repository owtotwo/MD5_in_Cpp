// demo.cpp
// A demo to show that how to use this library.

#include <iostream>
#include "md5.h"

int main() {
	std::string s = "abc"; // 0x3d 0x3e 0x3f in hexadecimal representation
	std::string result = MD5::md5(s); // return the encryption result in string 
	std::cout << "MD5 code for 'abc' is " << result << ".\n"; 
	// "MD5 code of 'abc' is 900150983cd24fb0d6963f7d28e17f72."
	return 0;
}
