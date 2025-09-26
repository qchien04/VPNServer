#include "common.h"
#include <vector>
#include <map>
#include "ChildSA.h"
#include <sstream>
#include <iomanip>
class IKESA {
private:
    uint64_t initiator_spi;
    uint64_t responder_spi;
    std::vector<uint8_t> sk_d, sk_ai, sk_ar, sk_ei, sk_er, sk_pi, sk_pr;
    std::vector<uint8_t> skeyseed;
    bool is_initiator;
    std::unique_ptr<ChildSA> fisrt_child_sa;
    std::map<uint32_t, ChildSA> child_sas;
    
public:
    IKESA(bool initiator) : is_initiator(initiator) {
        if (initiator) {
            generateSPI(initiator_spi);
        }
    }
    
    void generateSPI(uint64_t& spi) {
        CHECK_OPENSSL(RAND_bytes(reinterpret_cast<uint8_t*>(&spi), sizeof(spi)) == 1);
    }
    
    void createFirstChildSA(){
        fisrt_child_sa = std::make_unique<ChildSA>(is_initiator);
    }

    ChildSA* getFirstChildSA(){
        return fisrt_child_sa.get();
    }

    void deriveKeys(const std::vector<uint8_t>& dh_shared_secret,
                   const std::vector<uint8_t>& ni,
                   const std::vector<uint8_t>& nr) {
        // RFC 7296: SKEYSEED = prf(Ni | Nr, g^ir)
        std::vector<uint8_t> nonces = ni;
        nonces.insert(nonces.end(), nr.begin(), nr.end());
        skeyseed = IKECrypto::hmac_sha256(nonces, dh_shared_secret);
        
        // Derive all keys using PRF+
        // {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr} = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
        std::vector<uint8_t> seed = nonces;
        uint64_t ispi_be = htobe64(initiator_spi);
        uint64_t rspi_be = htobe64(responder_spi);
        seed.insert(seed.end(), reinterpret_cast<uint8_t*>(&ispi_be), 
                   reinterpret_cast<uint8_t*>(&ispi_be) + 8);
        seed.insert(seed.end(), reinterpret_cast<uint8_t*>(&rspi_be), 
                   reinterpret_cast<uint8_t*>(&rspi_be) + 8);
        
        // Generate enough key material for all keys (7 * 32 bytes = 224 bytes)
        std::vector<uint8_t> keymat = IKECrypto::prf_plus(skeyseed, seed, 7 * 32);
        
        // Extract individual keys (each 32 bytes for SHA-256 based PRF)
        size_t offset = 0;
        sk_d.assign(keymat.begin() + offset, keymat.begin() + offset + 32); offset += 32;
        sk_ai.assign(keymat.begin() + offset, keymat.begin() + offset + 32); offset += 32;
        sk_ar.assign(keymat.begin() + offset, keymat.begin() + offset + 32); offset += 32;
        sk_ei.assign(keymat.begin() + offset, keymat.begin() + offset + 32); offset += 32;
        sk_er.assign(keymat.begin() + offset, keymat.begin() + offset + 32); offset += 32;
        sk_pi.assign(keymat.begin() + offset, keymat.begin() + offset + 32); offset += 32;
        sk_pr.assign(keymat.begin() + offset, keymat.begin() + offset + 32);
    }
    
    void setResponderSPI(uint64_t spi) { responder_spi = spi; }
    void setInitiatorSPI(uint64_t spi) { initiator_spi = spi; }
    uint64_t getInitiatorSPI() const { return initiator_spi; }
    uint64_t getResponderSPI() const { return responder_spi; }
    
    const std::vector<uint8_t>& getSK_d() const { return sk_d; }
    const std::vector<uint8_t>& getSK_ai() const { return sk_ai; }
    const std::vector<uint8_t>& getSK_ar() const { return sk_ar; }
    const std::vector<uint8_t>& getSK_ei() const { return sk_ei; }
    const std::vector<uint8_t>& getSK_er() const { return sk_er; }
    const std::vector<uint8_t>& getSK_pi() const { return sk_pi; }
    const std::vector<uint8_t>& getSK_pr() const { return sk_pr; }
    
    std::vector<uint8_t> encryptPayload(const std::vector<uint8_t>& payload) const {
        // Generate random IV
        std::vector<uint8_t> iv(16);
        CHECK_OPENSSL(RAND_bytes(iv.data(), iv.size()) == 1);
        // std::cout<<"----------------key enc sk_ei "<<bytesToHex(sk_ei)<<std::endl;
        // std::cout<<"----------------key enc sk_er "<<bytesToHex(sk_er)<<std::endl;
        // Encrypt using SK_ei (initiator) or SK_er (responder)
        const std::vector<uint8_t>& encryption_key = is_initiator ? sk_ei : sk_er;
        // std::cout<<"----------------key enc "<<bytesToHex(encryption_key)<<std::endl;
        std::vector<uint8_t> encrypted = IKECrypto::aes_cbc_encrypt(encryption_key, iv, payload);
        
        // Prepend IV to encrypted data
        std::vector<uint8_t> result = iv;
        result.insert(result.end(), encrypted.begin(), encrypted.end());
        return result;
    }
    
    std::vector<uint8_t> decryptPayload(const std::vector<uint8_t>& encrypted_payload) const {
        if (encrypted_payload.size() < 16) {
            throw std::runtime_error("Invalid encrypted payload size");
        }
        
        // Extract IV and ciphertext
        std::vector<uint8_t> iv(encrypted_payload.begin(), encrypted_payload.begin() + 16);
        std::vector<uint8_t> ciphertext(encrypted_payload.begin() + 16, encrypted_payload.end());
        // std::cout<<"----------------key deenc sk_ei "<<bytesToHex(sk_ei)<<std::endl;
        // std::cout<<"----------------key deenc sk_er "<<bytesToHex(sk_er)<<std::endl;
        // Decrypt using SK_er (initiator) or SK_ei (responder)
        const std::vector<uint8_t>& decryption_key = is_initiator ? sk_er : sk_ei;
        //std::cout<<"----------------key decry "<<bytesToHex(decryption_key)<<std::endl;
        return IKECrypto::aes_cbc_decrypt(decryption_key, iv, ciphertext);
    }
    
    std::vector<uint8_t> calculateIntegrityChecksum(const std::vector<uint8_t>& data) const {
        // Use SK_ai (initiator) or SK_ar (responder) for integrity
        const std::vector<uint8_t>& integrity_key = is_initiator ? sk_ai : sk_ar;
        return IKECrypto::hmac_sha256(integrity_key, data);
    }
    
    bool verifyIntegrityChecksum(const std::vector<uint8_t>& data, const std::vector<uint8_t>& checksum) const {
        std::vector<uint8_t> calculated = calculateIntegrityChecksum(data);
        return calculated == checksum;
    }

    std::string bytesToHex(const std::vector<uint8_t>& data) const {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }

    std::string toString() const {
        std::ostringstream oss;
        oss << "=== IKESA State ===\n";
        oss << "- Role             : " << (is_initiator ? "Initiator" : "Responder") << "\n";
        oss << "- Initiator SPI    : 0x" << std::hex << initiator_spi << std::dec << "\n";
        oss << "- Responder SPI    : 0x" << std::hex << responder_spi << std::dec << "\n";

        oss << "- SK_d             : " << bytesToHex(sk_d) << "\n";
        oss << "- SK_ai            : " << bytesToHex(sk_ai) << "\n";
        oss << "- SK_ar            : " << bytesToHex(sk_ar) << "\n";
        oss << "- SK_ei            : " << bytesToHex(sk_ei) << "\n";
        oss << "- SK_er            : " << bytesToHex(sk_er) << "\n";
        oss << "- SK_pi            : " << bytesToHex(sk_pi) << "\n";
        oss << "- SK_pr            : " << bytesToHex(sk_pr) << "\n";
        oss << "====================";
        return oss.str();
    }
};
