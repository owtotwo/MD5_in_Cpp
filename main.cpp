// main.cpp
// Create an executable file for md5 encryption.

#include <iostream>
#include "md5.h"

using namespace std;

int main(int argc, char* argv[]) {
	if (argc > 1) {
		string filename = argv[1];
		if (filename[0] == '-') {
			cout << "You can use as \"md5 [file]\".\n";
			return 0;
		}
		cout << MD5::md5_file(filename) << endl;
	} else {
		string s;
		getline(cin, s);
		cout << MD5::md5(s) << endl;
	}
	return 0;
}
