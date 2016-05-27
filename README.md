# **MD5_in_Cpp** #
A MD5-encryption library implemented in C++.  
__*Copyright (c) 2016 sysu_AT < owtotwo@163.com >*__  


## How to Use ##

Just use `md5.h` for your project and call the function in namespace MD5.  

```
#include "md5.h"

MD5::md5("abc"); // "900150983cd24fb0d6963f7d28e17f72"

```

Or if you want to build an executable file for md5 encryption, you could:  

	`prompt> g++ main.cpp`
or use other compiler like clang :

	`prompt> clang++ main.cpp`
Add -std=c++11 flag whatever you want.


## License ##
* GNU Lesser General Public License ([LGPL](LICENSE))  
  http://www.gnu.org/licenses/lgpl-3.0.en.html
