#include "common.h"
#include "DHKeyExchange.h"
#include "PayloadHeader.h"
#include <sstream>
#include <iomanip>
class KEPayload {
private:
    DHGroup dh_group;
    std::unique_ptr<DHKeyExchange> dh_exchange;
    
public:
    KEPayload(DHGroup group) : dh_group(group) {
        dh_exchange = std::make_unique<DHKeyExchange>(group);
    }
    
    std::vector<uint8_t> getPublicKey() const {
        return dh_exchange->getPublicKey();
    }

    void setPeerKey(const std::vector<uint8_t>& peer_key) {
        dh_exchange->setPeerKey(peer_key);
    }

    std::vector<uint8_t> getPeerKey() const {
        return dh_exchange->getPeerKey();
    }
    
    std::vector<uint8_t> computeSharedSecret(const std::vector<uint8_t>& peer_key) {
        return dh_exchange->computeSharedSecret(peer_key);
    }
    
    std::vector<uint8_t> serialize() const {
        PayloadHeader header;
        header.next_payload = PayloadType::NO_NEXT_PAYLOAD;
        header.critical_flag = 0;
        
        std::vector<uint8_t> ke_data = getPublicKey();
        
        std::vector<uint8_t> payload_data;
        uint16_t group_be = host_to_net16(static_cast<uint16_t>(dh_group));
        payload_data.insert(payload_data.end(), 
                          reinterpret_cast<const uint8_t*>(&group_be),
                          reinterpret_cast<const uint8_t*>(&group_be) + 2);
        
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        
        payload_data.insert(payload_data.end(), ke_data.begin(), ke_data.end());
        
        header.payload_length = 4 + payload_data.size();
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), payload_data.begin(), payload_data.end());
        
        return result;
    }
    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }

    static KEPayload deserialize(const std::vector<uint8_t>& body) {
        if (body.size() < 4) {
            throw std::runtime_error("Invalid KE payload size");
        }

        // Lấy group id
        uint16_t group_be;
        memcpy(&group_be, body.data(), 2);
        DHGroup group = static_cast<DHGroup>(net_to_host16(group_be));

        // Bỏ qua 2 byte reserved
        std::vector<uint8_t> peer_key(body.begin() + 4, body.end());

        // Tạo KEPayload cho đúng group
        KEPayload ke(group);

        // Tính shared secret thì ta phải truyền peer_key vào
        // => lưu peer_key vào chỗ khác (chưa dùng ngay trong constructor)
        ke.dh_exchange->setPeerKey(peer_key); // cần thêm hàm này trong DHKeyExchange

        return ke;
    }

    // Lấy peer public key đã parse
    std::vector<uint8_t> getPeerPublicKey() const {
        return dh_exchange->getPeerKey();
    }

    DHGroup getDHGroup() const { return dh_group; }
};
