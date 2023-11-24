#include <bits/stdc++.h>
#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "sm9.h"

using c_ctx_t = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using md_ctx_t = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using pkey_ctx_t = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using pkey_t = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

/** Helper functions **/
std::vector<unsigned char> file2buffer(const char* filename) {
	std::ifstream file(filename, std::ios::binary | std::ios::ate);
	std::streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	std::vector<unsigned char> buffer(size);
	if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
		return buffer;
	}
	return {};
}

bool buffer2file(const char* filename, const std::vector<unsigned char>& buffer) {
	std::ofstream file(filename, std::ios::binary | std::ios::out);
	return file.write(reinterpret_cast<char const*>(buffer.data()), buffer.size()).good();
}

bool file2pkey(const char* filename, pkey_t &pkey) {
	FILE* pkey_fp = fopen(filename, "r");
	if (pkey_fp) {
		pkey.reset(PEM_read_PrivateKey(pkey_fp, nullptr, nullptr, nullptr));
		fclose(pkey_fp);
		return !(!pkey);
	}
	return false;
}

/** SM9 namespace functions **/
sm9::SM9_CODE sm9::sm2_sign(const std::string& file_to_sign,
					 const std::string& pkey_file,
					 const std::string& out_file,
					 const std::vector<unsigned char> sm2id) {

	if (sm2id.empty())
		return sm9::PARAM_ERROR;
	pkey_t pkey(EVP_PKEY_new(), EVP_PKEY_free);
	if (!file2pkey(pkey_file.c_str(), pkey)) {
		return sm9::FILE_ERROR;
	}
	std::vector<unsigned char> buffer_to_sign = file2buffer(file_to_sign.c_str());
	if (buffer_to_sign.empty())
		return sm9::FILE_ERROR;
	std::vector<unsigned char> signature(2048);// TODO: Signature should be fixed size
	md_ctx_t mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	pkey_ctx_t pkctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free);
	EVP_PKEY_CTX *pkctx_ptr = pkctx.get();
	EVP_PKEY_CTX_set1_id(pkctx_ptr, sm2id.data(), sm2id.size());
	EVP_MD_CTX_set_pkey_ctx(mdctx.get(), pkctx_ptr);
	if (!EVP_DigestSignInit(mdctx.get(), &pkctx_ptr, EVP_sm3(), nullptr, pkey.get())) {
		std::cerr << __func__ << ": Failed to initialize verfication" << std::endl;
		return sm9::SSL_ERROR;
	}
	if (!EVP_DigestSignUpdate(mdctx.get(), buffer_to_sign.data(), buffer_to_sign.size())) {
		std::cerr << __func__ << ": Failed to process the file to sign" << std::endl;
		return sm9::SSL_ERROR;
	}
	size_t final_len;
	if (!EVP_DigestSignFinal(mdctx.get(), signature.data(), &final_len)) {
		std::cerr << __func__ << ": Failed to sign the file" << std::endl;
		return sm9::SSL_ERROR;
	}
	signature.resize(final_len);
	if (!buffer2file(out_file.c_str(), signature)) {
		std::cerr << __func__ << ": Failed to write " << out_file << " file" << std::endl;
		return sm9::FILE_ERROR;
	}
	return sm9::OK;
}

sm9::SM9_CODE sm9::sm2_verify(const std::string& file_to_verify,
					 const std::string& pkey_file,
					 const std::string& signature_file,
					 const std::vector<unsigned char> sm2id) {
	
	if (sm2id.empty())
		return sm9::PARAM_ERROR;
	pkey_t pkey(EVP_PKEY_new(), EVP_PKEY_free);
	if (!file2pkey(pkey_file.c_str(), pkey)) {
		return sm9::FILE_ERROR;
	}
	std::vector<unsigned char> buffer_to_verify = file2buffer(file_to_verify.c_str());
	std::vector<unsigned char> signature = file2buffer(signature_file.c_str());
	if (buffer_to_verify.empty() || signature.empty())
		return sm9::FILE_ERROR;
	md_ctx_t mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	pkey_ctx_t pkctx(EVP_PKEY_CTX_new(pkey.get(), nullptr), EVP_PKEY_CTX_free);
	EVP_PKEY_CTX_set1_id(pkctx.get(), sm2id.data(), sm2id.size());
	EVP_MD_CTX_set_pkey_ctx(mdctx.get(), pkctx.get());
	if (!EVP_DigestVerifyInit(mdctx.get(), nullptr, EVP_sm3(), nullptr, pkey.get())) {
		std::cerr << __func__ << ": Failed to initiate verification" << std::endl;
		return sm9::SSL_ERROR;
	}
	if (!EVP_DigestVerifyUpdate(mdctx.get(), buffer_to_verify.data(), buffer_to_verify.size())) {
		std::cerr << __func__ << ": Failed to verify file" << std::endl;
		return sm9::SSL_ERROR;
	}
	if (!EVP_DigestVerifyFinal(mdctx.get(), signature.data(), signature.size())) {
		std::cerr << __func__ << ": Failed to verify signature" << std::endl;
		return sm9::SSL_ERROR;
	}
	return sm9::OK;
}

sm9::SM9_CODE sm9::sm3_hash(const std::vector<char>& buffer,
				  std::vector<unsigned char>& hash) {
	if (buffer.empty())
		return sm9::PARAM_ERROR;
	md_ctx_t mdctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
	hash.resize(EVP_MAX_MD_SIZE);//TODO: probably need to check if the resize went well ?
	unsigned int md_len;
	if (!EVP_DigestInit_ex(mdctx.get(), EVP_sm3(), nullptr)) {
		std::cerr << __func__ << ": Failed to initiate hash" << std::endl;
		return sm9::SSL_ERROR;
	}
	if (!EVP_DigestUpdate(mdctx.get(), buffer.data(), buffer.size())) {
		std::cerr << __func__ << ": Failed to load buffer" << std::endl;
		return sm9::SSL_ERROR;
	}
	if (!EVP_DigestFinal_ex(mdctx.get(), hash.data(), &md_len)) {
		std::cerr << __func__ << ": Failed to compute hash" << std::endl;
		return sm9::SSL_ERROR;
	}
	hash.resize(md_len);
	return sm9::OK;
}

sm9::SM9_CODE sm9::sm4_encrypt(const std::vector<unsigned char>& in_buffer,
					 const std::array<unsigned char, 16>& key,
					 const std::array<unsigned char, 8>& iv,
					 std::vector<unsigned char>& out_buffer) {
	out_buffer.resize(in_buffer.size()*4);
	if (out_buffer.empty())
		return sm9::PARAM_ERROR;
	c_ctx_t cctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!EVP_EncryptInit_ex2(cctx.get(), EVP_sm4_cbc(), key.data(), iv.data(), nullptr)) {
		std::cerr << __func__ << ": Failed to initialize encryption" << std::endl;
		return sm9::SSL_ERROR;
	}
	int outl;
	if (!EVP_EncryptUpdate(cctx.get(), out_buffer.data(), &outl,
						in_buffer.data(), in_buffer.size())) {
		std::cerr << __func__ << ": Failed to encrypt" << std::endl;
		return sm9::SSL_ERROR;
	}
	int outl2;
	if (!EVP_EncryptFinal(cctx.get(), out_buffer.data()+outl, &outl2)) {
		std::cerr << __func__ << ": Failed to finalize encryption" << std::endl;
		return sm9::SSL_ERROR;
	}
	out_buffer.resize(outl+outl2);
	return sm9::OK;
}

sm9::SM9_CODE sm9::sm4_decrypt(const std::vector<unsigned char>& in_buffer,
					 const std::array<unsigned char, 16>& key,
					 const std::array<unsigned char, 8>& iv,
					 std::vector<unsigned char>& out_buffer) {
	out_buffer.resize(in_buffer.size());
	if (out_buffer.empty())
		return sm9::PARAM_ERROR;
	c_ctx_t cctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!EVP_DecryptInit_ex2(cctx.get(), EVP_sm4_cbc(), key.data(), iv.data(), nullptr)) {
		std::cerr << __func__ << ": Failed to initialize decryption" << std::endl;
		return sm9::SSL_ERROR;
	}
	int outl;
	if (!EVP_DecryptUpdate(cctx.get(), out_buffer.data(), &outl,
						in_buffer.data(), in_buffer.size())) {
		std::cerr << __func__ << ": Failed to decrypt" << std::endl;
		return sm9::SSL_ERROR;
	}
	int outl2;
	if (!EVP_DecryptFinal(cctx.get(), out_buffer.data()+outl, &outl2)) {
		std::cerr << __func__ << ": Failed to finalize encryption" << std::endl;
		return sm9::SSL_ERROR;
	}
	out_buffer.resize(outl+outl2);
	return sm9::OK;
}
