// Documentation https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit.html
#include "sm9.h"

int main (int ac, char*av[]) {
	if (ac != 2) {
		std::cout << "Usage: " << av[0] << " <text_to_hash>" << std::endl;
		return -1;
	}
	std::vector<char> in(av[1], av[1]+strlen(av[1]));
	std::vector<unsigned char> out;
	sm9::sm3_hash(in, out);
	for (unsigned int i = 0; i < out.size(); i++)
         printf("%02x", out[i]);
	std::cout << std::endl;
	return 0;
}
