
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
class DHKeyExchange {
private:
    DH* dh;
    BIGNUM* private_key;
    BIGNUM* public_key;
    BIGNUM* peer_key; 
    DHGroup group;
    
public:
    DHKeyExchange(DHGroup dh_group) : dh(nullptr), private_key(nullptr), public_key(nullptr), peer_key(nullptr), group(dh_group) {
        initializeDH();
    }
    
    ~DHKeyExchange() {
        if (peer_key) BN_free(peer_key);
        if (dh) DH_free(dh);
    }


    void setPeerKey(const std::vector<uint8_t>& peer_public_key) {
        if (peer_key) { BN_free(peer_key); peer_key = nullptr; }
        peer_key = BN_bin2bn(peer_public_key.data(), (int)peer_public_key.size(), nullptr);
        if (!peer_key) throw std::runtime_error("BN_bin2bn failed for peer key");
        CHECK_OPENSSL(peer_key);
    }

    std::vector<uint8_t> getPeerKey() const {
        if (!peer_key) return {};
        int key_size = BN_num_bytes(peer_key);
        std::vector<uint8_t> key_data(key_size);
        BN_bn2bin(peer_key, key_data.data());
        return key_data;
    }
    
    void initializeDH() {
        dh = DH_new();
        CHECK_OPENSSL(dh);
        
        // Set DH parameters based on group
        BIGNUM* p = nullptr;
        BIGNUM* g = nullptr;
        
        switch (group) {
            case DHGroup::MODP_2048: {
                // MODP 2048-bit group (RFC 3526)
                static const char modp2048_p[] = 
                    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
                    
                CHECK_OPENSSL(BN_hex2bn(&p, modp2048_p));
                CHECK_OPENSSL(BN_dec2bn(&g, "2"));
                break;
            }
            default:
                throw std::runtime_error("Unsupported DH group");
        }
        
        CHECK_OPENSSL(DH_set0_pqg(dh, p, nullptr, g));
        
        // Generate key pair
        CHECK_OPENSSL(DH_generate_key(dh));
        
        // Get the keys
        const BIGNUM* pub_key;
        const BIGNUM* priv_key;
        DH_get0_key(dh, &pub_key, &priv_key);
        
        public_key = BN_dup(pub_key);
        private_key = BN_dup(priv_key);
        CHECK_OPENSSL(public_key && private_key);
    }
    
    std::vector<uint8_t> getPublicKey() const {
        int key_size = BN_num_bytes(public_key);
        std::vector<uint8_t> key_data(key_size);
        BN_bn2bin(public_key, key_data.data());
        return key_data;
    }
    
    std::vector<uint8_t> computeSharedSecret(const std::vector<uint8_t>& peer_public_key) {
        BIGNUM* peer_key = BN_bin2bn(peer_public_key.data(), peer_public_key.size(), nullptr);
        CHECK_OPENSSL(peer_key);
        
        int shared_size = DH_size(dh);
        std::vector<uint8_t> shared_secret(shared_size);
        
        int result = DH_compute_key(shared_secret.data(), peer_key, dh);
        BN_free(peer_key);
        
        if (result < 0) {
            throw std::runtime_error("DH shared secret computation failed");
        }
        
        shared_secret.resize(result);
        return shared_secret;
    }
    std::vector<uint8_t> computeSharedSecret() {
        if (!peer_key) {
            throw std::runtime_error("Peer key not set");
        }

        int shared_size = DH_size(dh);
        std::vector<uint8_t> shared_secret(shared_size);

        int result = DH_compute_key(shared_secret.data(), peer_key, dh);
        if (result < 0) {
            throw std::runtime_error("DH shared secret computation failed");
        }

        shared_secret.resize(result);
        return shared_secret;
    }
    
    DHGroup getGroup() const { return group; }
};
