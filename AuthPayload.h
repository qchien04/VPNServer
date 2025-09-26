#include "common.h"
#include <vector>
#include "PayloadHeader.h"
#include "IKECrypto.h"
#include <sstream>
#include <iomanip>
class AuthPayload {
private:
    uint8_t auth_method;
    std::vector<uint8_t> auth_data;
    
public:
    enum AuthMethod : uint8_t {
        RSA_DIGITAL_SIGNATURE = 1,
        SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2,
        DSS_DIGITAL_SIGNATURE = 3,
        ECDSA_SHA256 = 9,
        ECDSA_SHA384 = 10,
        ECDSA_SHA512 = 11
    };
    
    AuthPayload(AuthMethod method, const std::vector<uint8_t>& data) : auth_method(method), auth_data(data) {}
    
    std::vector<uint8_t> serialize() const {
        PayloadHeader header;
        header.next_payload = PayloadType::NO_NEXT_PAYLOAD;
        header.critical_flag = 0;
        
        std::vector<uint8_t> payload_data;
        payload_data.push_back(auth_method);
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        
        payload_data.insert(payload_data.end(), auth_data.begin(), auth_data.end());
        
        header.payload_length = 4 + payload_data.size();
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), payload_data.begin(), payload_data.end());
        
        return result;
    }

    std::vector<uint8_t> serialize(PayloadType payloadType) const {
        PayloadHeader header;
        header.next_payload = payloadType;
        header.critical_flag = 0;
        
        std::vector<uint8_t> payload_data;
        payload_data.push_back(auth_method);
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        
        payload_data.insert(payload_data.end(), auth_data.begin(), auth_data.end());
        
        header.payload_length = 4 + payload_data.size();
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), payload_data.begin(), payload_data.end());
        
        return result;
    }
    
    static std::vector<uint8_t> calculatePSKAuth(const std::vector<uint8_t>& psk,
                                                 const std::vector<uint8_t>& sk_p,
                                                 const std::vector<uint8_t>& id_payload,
                                                 const std::vector<uint8_t>& sa_init_msg) {
        // AUTH = prf(prf(Shared Secret, "Key Pad for IKEv2"), <InitiatorSignedOctets>)
        std::string key_pad = "Key Pad for IKEv2";
        std::vector<uint8_t> key_pad_vec(key_pad.begin(), key_pad.end());
        
        std::vector<uint8_t> auth_key = IKECrypto::hmac_sha256(psk, key_pad_vec);
        
        // Calculate signed octets: SA_INIT message + Ni/Nr + prf(SK_pi/pr, IDi/IDr)
        std::vector<uint8_t> signed_octets = sa_init_msg;
        std::vector<uint8_t> id_hash = IKECrypto::hmac_sha256(sk_p, id_payload);
        signed_octets.insert(signed_octets.end(), id_hash.begin(), id_hash.end());
        
        return IKECrypto::hmac_sha256(auth_key, signed_octets);
    }

    static AuthPayload deserialize(const std::vector<uint8_t>& data, size_t offset) {
        if (offset + 8 > data.size()) { // 4 byte header + 4 byte auth tối thiểu
            throw std::runtime_error("Invalid Auth payload: too short");
        }

        // B1: Deserialize header
        PayloadHeader header = PayloadHeader::deserialize(data, offset);

        if (header.payload_length < 8) {
            throw std::runtime_error("Invalid Auth payload length");
        }
        if (offset + header.payload_length > data.size()) {
            throw std::runtime_error("Auth payload length exceeds packet size");
        }

        // B2: Đọc Auth Method
        uint8_t method = data[offset + 4];

        // B3: Bỏ qua 3 byte reserved (offset+5,6,7)

        // B4: Lấy Auth Data
        std::vector<uint8_t> auth_data(
            data.begin() + offset + 8,
            data.begin() + offset + header.payload_length
        );

        return AuthPayload(static_cast<AuthMethod>(method), auth_data);
    }
    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }

    void debugPrint(int indent = 0) const {
        std::string pad(indent, ' ');
        std::cout << pad << "Auth Payload:" << "\n";
        std::cout << pad << "  Auth Method = " << (int)auth_method << "\n";
        std::cout << pad << "  Auth Data   = 0x" << bytesToHex(auth_data) << "\n";
    }

};
