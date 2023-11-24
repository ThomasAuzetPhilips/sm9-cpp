/**
* Documentation
* https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit.html
* https://www.openssl.org/docs/man3.0/man7/SM2.html
*/
#include "sm9.h"

int main (int ac, char*av[]) {
	if (ac != 3) {
		std::cout << "Usage: " << av[0] << " <pkey> <file_to_sign>" << std::endl;
		return -1;
	}
	const std::vector<unsigned char> id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
	switch (sm9::sm2_sign(av[2], av[1], "out.sign", id)) {
		case sm9::OK:
			std::cout << "Signed !" << std::endl;
		break;
		case sm9::PARAM_ERROR:
			std::cout << "Bad parameter" << std::endl;
		break;
		case sm9::FILE_ERROR:
			std::cout << "File error" << std::endl;
		break;
		case sm9::SSL_ERROR:
			std::cout << "Failed to sign" << std::endl;
		break;
	}
	return 0;
}
