#include "common.h"
#include <vector>
#include "PayloadHeader.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/err.h>

class NoncePayload {
private:
    std::vector<uint8_t> nonce_data;
    
public:
    NoncePayload() {
        generateNonce();
    }
    
    void generateNonce() {
        nonce_data.resize(32); // 256-bit nonce
        CHECK_OPENSSL(RAND_bytes(nonce_data.data(), nonce_data.size()) == 1);
    }
    
    const std::vector<uint8_t>& getNonce() const { return nonce_data; }
    
    std::vector<uint8_t> serialize() const {
        PayloadHeader header;
        header.next_payload = PayloadType::NO_NEXT_PAYLOAD;
        header.critical_flag = 0;
        header.payload_length = 4 + nonce_data.size();
        
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), nonce_data.begin(), nonce_data.end());
        
        return result;
    }
};

