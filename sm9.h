#include <bits/stdc++.h>

/**
 * Series of functions to implement various SM9 standards:
 *
 * SM2 - an Elliptic Curve Diffie-Hellman key agreement and signature
 * using a specified 256-bit elliptic curve.
 *
 * SM3 - a 256-bit cryptographic hash function.
 *
 * SM4 - a 128-bit block cipher with a 128-bit key.
 *
 * Tested with OpenSSL 3.0
 * Compile with -lssl -lcrypto
 */

namespace sm9 {

enum SM9_CODE {
	OK,
	PARAM_ERROR,//One of the parameter is invalid
	FILE_ERROR,//filesystem related issue (right problem, file not found, etc.)
	SSL_ERROR//internal OpenSSL issue (key not valid, oom, etc.)
};

/**
* sm2_sign function
* Will generate a signature file using an sm2 pem key
*
* @param file_to_sign: Path of the file to generate the signature
* @param pkey_file: Path of the SM2 key file
* @param out_file: File to write the signature, the function will generate it if
* 					it does not exists
* @param sm2id: SM2 ID to provide, required for SM2 key usage
*
* @return: SM9_CODE::OK if successfully signed
*/
SM9_CODE sm2_sign(const std::string& file_to_sign,
					 const std::string& pkey_file,
					 const std::string& out_file,
					 const std::vector<unsigned char> sm2id);

/**
* sm2_verify function
* Will check for the validity of a sm2 signature
*
* @param file_to_verify: Path of the file that was previously signed
* @param pkey_file: Path of the SM2 key file
* @param signature_file: Path of the signature file
* @param sm2id: SM2 ID to provide, required for SM2 key usage, must be
* 				the same as the one used for signing
*
* @return: SM9_CODE::OK if the signature is valid
*/
SM9_CODE sm2_verify(const std::string& file_to_verify,
					 const std::string& pkey_file,
					 const std::string& signature_file,
					 const std::vector<unsigned char> sm2id);

/**
* sm3_hash function
* Will compute the hash of a buffer using sm3 function
*
* @param buffer: Buffer to compute the hash from
* @param hash: Resulting hash
*
* @return: SM9_CODE::OK if the hash have been computed
*/
SM9_CODE sm3_hash(const std::vector<char>& buffer,
				  std::vector<unsigned char>& hash);

/**
* sm4_encrypt function
* Will encrypt a buffer using the SM4 block cipher
*
* @param in_buffer: Buffer to encrypt
* @param key: 128-bit key to use for encryption
* @param iv: 64-bit IV to use for encryption
* @param out_buffer: Resulting encrypted buffer
*
* @return: SM9_CODE::OK if the encryption is complete
*/
SM9_CODE sm4_encrypt(const std::vector<unsigned char>& in_buffer,
					 const std::array<unsigned char, 16>& key,
					 const std::array<unsigned char, 8>& iv,
					 std::vector<unsigned char>& out_buffer);

/**
* sm4_decrypt function
* Will decrypt a buffer using the SM4 block cipher
*
* @param in_buffer: Buffer to decrypt
* @param key: 128-bit key to use for decryption
* @param iv: 64-bit IV to use for decryption
* @param out_buffer: Resulting decrypted buffer
*
* @return: SM9_CODE::OK if the decryption is complete
*/
SM9_CODE sm4_decrypt(const std::vector<unsigned char>& in_buffer,
					 const std::array<unsigned char, 16>& key,
					 const std::array<unsigned char, 8>& iv,
					 std::vector<unsigned char>& out_buffer);
}

