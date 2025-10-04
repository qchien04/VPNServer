#include "common.h"
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "TrafficSelector.h"
#include "IKECrypto.h"

class ChildSA {
private:
    uint32_t spi_inbound;
    uint32_t spi_outbound;
    std::vector<uint8_t> sk_ei, sk_er, sk_ai, sk_ar; // Child SA keys
    bool is_initiator;
    
    // IPSec parameters
    uint8_t protocol_id; // ESP or AH
    EncryptionAlgorithm encryption_alg;
    IntegrityAlgorithm integrity_alg;
    
    // Traffic Selectors
    std::vector<TrafficSelector> ts_initiator;
    std::vector<TrafficSelector> ts_responder;
    
public:
    ChildSA(bool initiator, uint8_t proto_id = static_cast<uint8_t>(ProtocolID::ESP)) 
        : is_initiator(initiator), protocol_id(proto_id),
          encryption_alg(EncryptionAlgorithm::AES_CBC_256),
          integrity_alg(IntegrityAlgorithm::AUTH_HMAC_SHA256_128) {
        generateSPIs();
    }
    
    void generateSPIs() {
        CHECK_OPENSSL(RAND_bytes(reinterpret_cast<uint8_t*>(&spi_outbound), sizeof(spi_outbound)) == 1);
    }
    void setSpiInbound(uint32_t spi_inbound) {
        this->spi_inbound = spi_inbound;
    }
    void deriveKeys(const std::vector<uint8_t>& sk_d, 
                   const std::vector<uint8_t>& ni, 
                   const std::vector<uint8_t>& nr) {
        // RFC 7296: Child SA key derivation
        // KEYMAT = prf+(SK_d, Ni | Nr | SPIi | SPIr)
        
        std::vector<uint8_t> seed;
        seed.insert(seed.end(), ni.begin(), ni.end());
        seed.insert(seed.end(), nr.begin(), nr.end());

        // Determine SPIi and SPIr according to role
        uint32_t spi_i = is_initiator ? spi_inbound : spi_outbound; // initiator SPI
        uint32_t spi_r = is_initiator ? spi_outbound  : spi_inbound; // responder SPI
        
        uint32_t spi_i_be = host_to_net32(spi_i);
        uint32_t spi_r_be = host_to_net32(spi_r);
        seed.insert(seed.end(), reinterpret_cast<uint8_t*>(&spi_i_be), reinterpret_cast<uint8_t*>(&spi_i_be) + 4);
        seed.insert(seed.end(), reinterpret_cast<uint8_t*>(&spi_r_be), reinterpret_cast<uint8_t*>(&spi_r_be) + 4);


        // compute lengths
        size_t len_e = 32;
        size_t len_a = 32;
        // ordering: SK_ei | SK_ai | SK_er | SK_ar  (initiator->responder first)
        size_t total = (len_e + len_a) * 2;

        std::vector<uint8_t> keymat = IKECrypto::prf_plus(sk_d, seed, total);
        if (keymat.size() < total) throw std::runtime_error("prf_plus returned insufficient key material");

        size_t offset = 0;
        sk_ei.assign(keymat.begin() + offset, keymat.begin() + offset + len_e); offset += len_e;
        sk_ai.assign(keymat.begin() + offset, keymat.begin() + offset + len_a); offset += len_a;
        sk_er.assign(keymat.begin() + offset, keymat.begin() + offset + len_e); offset += len_e;
        sk_ar.assign(keymat.begin() + offset, keymat.begin() + offset + len_a); // offset += len_a;

    }
    const std::vector<uint8_t>& outboundEncKey() const {
        return is_initiator ? sk_ei : sk_er;
    }
    const std::vector<uint8_t>& outboundAuthKey() const {
        return is_initiator ? sk_ai : sk_ar;
    }
    // For receiving (inbound): inverse
    const std::vector<uint8_t>& inboundEncKey() const {
        return is_initiator ? sk_er : sk_ei;
    }
    const std::vector<uint8_t>& inboundAuthKey() const {
        return is_initiator ? sk_ar : sk_ai;
    }
    
    void setTrafficSelectors(const std::vector<TrafficSelector>& tsi, 
                           const std::vector<TrafficSelector>& tsr) {
        ts_initiator = tsi;
        ts_responder = tsr;
    }
    
    void setTrafficSelectorsI(const std::vector<TrafficSelector>& tsi) {
        ts_initiator = tsi;
    }

    void setTrafficSelectorsR(const std::vector<TrafficSelector>& tsr) {
        ts_responder = tsr;
    }

    void addTrafficSelectorsI(TrafficSelector tsi) {
        ts_initiator.push_back(tsi);
    }
    void addTrafficSelectorsR(TrafficSelector tsr) {
        ts_responder.push_back(tsr);
    }
    // ESP Packet processing
    std::vector<uint8_t> encryptESP(const std::vector<uint8_t>& plaintext, uint32_t seq_num) const {
        // Construct ESP packet: SPI(4) | Seq(4) | IV | Encrypted(Payload|Pad|PadLen|NextHeader) | ICV
        std::vector<uint8_t> esp_packet;

        uint32_t spi_be = host_to_net32(spi_outbound);
        uint32_t seq_be = host_to_net32(seq_num);

        esp_packet.insert(esp_packet.end(), reinterpret_cast<uint8_t*>(&spi_be), reinterpret_cast<uint8_t*>(&spi_be) + 4);
        esp_packet.insert(esp_packet.end(), reinterpret_cast<uint8_t*>(&seq_be), reinterpret_cast<uint8_t*>(&seq_be) + 4);

        // IV size for AES-CBC
        const size_t iv_len = 16;
        std::vector<uint8_t> iv(iv_len);
        CHECK_OPENSSL(RAND_bytes(iv.data(), iv.size()) == 1);
        esp_packet.insert(esp_packet.end(), iv.begin(), iv.end());

        // Build payload + padding + PadLen + NextHeader
        std::vector<uint8_t> payload = plaintext;
        const size_t block_size = 16;
        // Pad so that (payload + pad_len + 2) % block_size == 0
        size_t pad_len = (block_size - ((payload.size() + 2) % block_size)) % block_size;
        for (size_t i = 0; i < pad_len; ++i) {
            payload.push_back(static_cast<uint8_t>(i + 1));
        }
        payload.push_back(static_cast<uint8_t>(pad_len));               // Pad Length
        payload.push_back(static_cast<uint8_t>(protocol_id));          // Next Header

        // Encrypt with outbound encryption key
        const std::vector<uint8_t>& encKey = outboundEncKey();
        std::vector<uint8_t> encrypted = IKECrypto::aes_cbc_encrypt(encKey, iv, payload);
        esp_packet.insert(esp_packet.end(), encrypted.begin(), encrypted.end());

        // ICV: compute over entire packet so far
        const std::vector<uint8_t>& authKey = outboundAuthKey();
        std::vector<uint8_t> icv = IKECrypto::hmac_sha256(authKey, esp_packet);
        icv.resize(32); // truncate
        esp_packet.insert(esp_packet.end(), icv.begin(), icv.end());

        return esp_packet;
    }

    std::vector<uint8_t> decryptESP(const std::vector<uint8_t>& esp_packet) const {
        // minimal length check: 8 (hdr) + iv + min ciphertext + ICV
        const size_t iv_len = 16;
        const size_t icv_len = 32;
        if (esp_packet.size() < 8 + iv_len + 1 + icv_len) {
            throw std::runtime_error("ESP packet too short");
        }

        // Extract SPI and Seq if needed
        // uint32_t spi_recv = ntohl(*reinterpret_cast<const uint32_t*>(esp_packet.data())); // careful with alignment; omitted here

        // Separate parts
        size_t header_end = 8;
        std::vector<uint8_t> iv(esp_packet.begin() + header_end, esp_packet.begin() + header_end + iv_len);
        std::vector<uint8_t> encrypted_payload(esp_packet.begin() + header_end + iv_len, esp_packet.end() - icv_len);
        std::vector<uint8_t> received_icv(esp_packet.end() - icv_len, esp_packet.end());

        // Verify ICV using inbound auth key
        const std::vector<uint8_t>& authKey = inboundAuthKey();
        std::vector<uint8_t> packet_without_icv(esp_packet.begin(), esp_packet.end() - icv_len);
        std::vector<uint8_t> calculated_icv = IKECrypto::hmac_sha256(authKey, packet_without_icv);
        calculated_icv.resize(icv_len);
        if (calculated_icv != received_icv) {
            throw std::runtime_error("ESP ICV verification failed");
        }

        // Decrypt with inbound enc key
        const std::vector<uint8_t>& encKey = inboundEncKey();
        std::vector<uint8_t> decrypted = IKECrypto::aes_cbc_decrypt(encKey, iv, encrypted_payload);

        if (decrypted.size() < 2) throw std::runtime_error("Decrypted payload too short");

        uint8_t pad_len = decrypted[decrypted.size() - 2];
        uint8_t next_header = decrypted[decrypted.size() - 1];

        if (decrypted.size() < (size_t)pad_len + 2) throw std::runtime_error("Invalid padding length");

        decrypted.resize(decrypted.size() - pad_len - 2); // remove pad + pad_len + next header
        return decrypted;
    }
    uint32_t getInboundSPI() const { return spi_inbound; }
    uint32_t getOutboundSPI() const { return spi_outbound; }
    
    std::string toString() const {
        std::cout<<"vai lon\n";
        std::ostringstream oss;
        oss << "=== Child SA ===\n";
        oss << "Role: " << (is_initiator ? "Initiator" : "Responder") << "\n";
        oss << "Inbound SPI:  0x" << std::hex << spi_inbound << "\n";
        oss << "Outbound SPI: 0x" << std::hex << spi_outbound << "\n";
        oss << "Protocol: " << (int)protocol_id << "\n";

        oss<<" sk_ei "<<bytesToHex(sk_ei)<<std::endl;
        oss<<" sk_er "<<bytesToHex(sk_er)<<std::endl;
        oss<<" sk_ai "<<bytesToHex(sk_ai)<<std::endl;
        oss<<" sk_ar "<<bytesToHex(sk_ar)<<std::endl;
        oss << "===============\n";
        return oss.str();
    }
    
    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }
};
