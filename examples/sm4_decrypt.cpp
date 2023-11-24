// Documentation https://www.openssl.org/docs/man3.0/man3/EVP_EncryptInit.html
#include "sm9.h"

std::vector<unsigned char> file2buffer_(const char* filename) {
	std::ifstream file(filename, std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	std::vector<unsigned char> buffer(size);
	if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
		return buffer;
	}
	std::cerr << "Failed to read " << filename << std::endl;
	return {};
}

bool buffer2file_(const char* filename, const std::vector<unsigned char>& buffer) {
	std::ofstream file(filename, std::ios::binary | std::ios::out);
	return file.write(reinterpret_cast<char const*>(buffer.data()), buffer.size()).good();
}

int main (int ac, char*av[]) {
	std::array<unsigned char, 16> key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	std::array<unsigned char, 8> iv = {1,2,3,4,5,6,7,8};
	if (ac != 2) {
		std::cout << "Usage: " << av[0] << " <file_to_decrypt>" << std::endl;
		return -1;
	}
	std::vector<unsigned char> enc_buffer = file2buffer_(av[1]);
	std::vector<unsigned char> clear_buffer;
	switch (sm9::sm4_decrypt(enc_buffer, key, iv, clear_buffer)) {
		case sm9::OK:
			std::cout << "Decrypted !" << std::endl;
		break;
		case sm9::PARAM_ERROR:
			std::cout << "Bad parameter" << std::endl;
		break;
		case sm9::FILE_ERROR:
			std::cout << "File error" << std::endl;
		break;
		case sm9::SSL_ERROR:
			std::cout << "Failed to decrypt" << std::endl;
		break;
	}
	if (!buffer2file_("out.txt", clear_buffer)) {
		std::cerr << "Failed to write result" << std::endl;
	}
	return 0;
}
