#pragma once
#include "common.h"
#include <vector>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>
// Cryptographic operations
class IKECrypto {
public:
    static std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result(32);
        unsigned int len;
        
        CHECK_OPENSSL(HMAC(EVP_sha256(), key.data(), key.size(), 
                          data.data(), data.size(), result.data(), &len));
        
        result.resize(len);
        return result;
    }
    
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result(32);
        CHECK_OPENSSL(SHA256(data.data(), data.size(), result.data()));
        return result;
    }
    
    static std::vector<uint8_t> prf_plus(const std::vector<uint8_t>& key, 
                                        const std::vector<uint8_t>& seed, 
                                        size_t output_length) {
        std::vector<uint8_t> result;
        std::vector<uint8_t> t;
        uint8_t counter = 1;
        
        while (result.size() < output_length) {
            std::vector<uint8_t> input = t;
            input.insert(input.end(), seed.begin(), seed.end());
            input.push_back(counter);
            
            t = hmac_sha256(key, input);
            result.insert(result.end(), t.begin(), t.end());
            counter++;
        }
        
        result.resize(output_length);
        return result;
    }
    
    static std::vector<uint8_t> aes_cbc_encrypt(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& iv,
                                               const std::vector<uint8_t>& plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        CHECK_OPENSSL(ctx);
        
        std::vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len, ciphertext_len;
        
        CHECK_OPENSSL(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()));
        CHECK_OPENSSL(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()));
        ciphertext_len = len;
        CHECK_OPENSSL(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len));
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }
    
    static std::vector<uint8_t> aes_cbc_decrypt(const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& iv,
                                               const std::vector<uint8_t>& ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        CHECK_OPENSSL(ctx);
        
        std::vector<uint8_t> plaintext(ciphertext.size());
        int len, plaintext_len;
        
        CHECK_OPENSSL(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()));
        CHECK_OPENSSL(EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()));
        plaintext_len = len;
        CHECK_OPENSSL(EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len));
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);
        return plaintext;
    }
};