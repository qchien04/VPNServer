#include "common.h"
#include <vector>
#include "PayloadHeader.h"
#include <sstream>
#include <iomanip>
class IdentityPayload {
private:
    uint8_t id_type;
    std::vector<uint8_t> id_data;
    
public:
    enum IDType : uint8_t {
        ID_IPV4_ADDR = 1,
        ID_FQDN = 2,
        ID_RFC822_ADDR = 3,
        ID_IPV6_ADDR = 5,
        ID_DER_ASN1_DN = 9,
        ID_DER_ASN1_GN = 10,
        ID_KEY_ID = 11
    };
    
    IdentityPayload(IDType type, const std::vector<uint8_t>& data) : id_type(type), id_data(data) {}
    
    std::vector<uint8_t> serialize() const {
        PayloadHeader header;
        header.next_payload = PayloadType::NO_NEXT_PAYLOAD;
        header.critical_flag = 0;
        
        std::vector<uint8_t> payload_data;
        payload_data.push_back(id_type);
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        
        payload_data.insert(payload_data.end(), id_data.begin(), id_data.end());
        
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
        payload_data.push_back(id_type);
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        
        payload_data.insert(payload_data.end(), id_data.begin(), id_data.end());
        
        header.payload_length = 4 + payload_data.size();
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), payload_data.begin(), payload_data.end());
        
        return result;
    }

    static IdentityPayload deserialize(const std::vector<uint8_t>& data, size_t offset) {
        if (offset + 8 > data.size()) {
            throw std::runtime_error("Invalid Identity payload: too short");
        }

        // Đọc header
        PayloadHeader header = PayloadHeader::deserialize(data, offset);
        if (header.payload_length < 8) {
            throw std::runtime_error("Invalid Identity payload length");
        }
        if (offset + header.payload_length > data.size()) {
            throw std::runtime_error("Identity payload length exceeds packet size");
        }

        // Đọc ID Type
        uint8_t id_type = data[offset + 4];

        // Bỏ qua 3 byte reserved (offset+5,6,7)
        std::vector<uint8_t> id_data(
            data.begin() + offset + 8,
            data.begin() + offset + header.payload_length
        );

        return IdentityPayload(static_cast<IDType>(id_type), id_data);
    }
    void debugPrint(int indent = 0) const {
        std::string pad(indent, ' ');
        std::cout << pad << "Identity Payload:" << "\n";
        std::cout << pad << "  ID Type = " << (int)id_type << "\n";
        std::cout << pad << "  Data    = " << std::string(id_data.begin(), id_data.end()) << "\n";
    }
};
