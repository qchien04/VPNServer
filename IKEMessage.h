#include "common.h"
#include "IKEHeader.h"
#include "PayloadHeader.h"
#include <vector>

class IKEMessage {
private:
    IKEHeader header;
    std::vector<std::pair<PayloadType, std::vector<uint8_t>>> payloads;
    
public:
    IKEMessage(IKEMessageType msg_type) {
        header.exchange_type = msg_type;
        header.version = 0x20; // IKEv2
    }
    
    void setHeader(const IKEHeader& h) { header = h; }
    const IKEHeader& getHeader() const { return header; }
    
    void addPayload(PayloadType type, const std::vector<uint8_t>& payload_data) {
        payloads.push_back(std::make_pair(type, payload_data));
    }
    
    std::vector<uint8_t> serialize() const {
        // Update header with proper payload chaining
        IKEHeader updated_header = header;
        if (!payloads.empty()) {
            updated_header.next_payload = payloads[0].first;
        }
        
        std::vector<uint8_t> message;
        std::vector<uint8_t> all_payloads;
        
        // Chain payloads properly
        for (size_t i = 0; i < payloads.size(); ++i) {
            std::vector<uint8_t> payload_data = payloads[i].second;
            
            // Update next_payload field in payload header
            if (i < payloads.size() - 1) {
                payload_data[0] = static_cast<uint8_t>(payloads[i + 1].first);
            } else {
                payload_data[0] = static_cast<uint8_t>(PayloadType::NO_NEXT_PAYLOAD);
            }
            
            all_payloads.insert(all_payloads.end(), payload_data.begin(), payload_data.end());
        }
        
        // Update total length
        updated_header.length = 28 + all_payloads.size(); // IKE header is 28 bytes
        
        // Serialize header
        std::vector<uint8_t> header_data = updated_header.serialize();
        message.insert(message.end(), header_data.begin(), header_data.end());
        
        // Add all payloads
        message.insert(message.end(), all_payloads.begin(), all_payloads.end());
        
        return message;
    }
    
    static IKEMessage deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 28) {
            throw std::runtime_error("Invalid IKE message size");
        }
        
        IKEHeader header = IKEHeader::deserialize(data);
        IKEMessage message(header.exchange_type);
        message.setHeader(header);
        
        // Parse payloads
        size_t offset = 28;
        PayloadType current_payload = header.next_payload;
        
        while (current_payload != PayloadType::NO_NEXT_PAYLOAD && offset < data.size()) {
            if (offset + 4 > data.size()) break;
            
            PayloadHeader payload_header = PayloadHeader::deserialize(data, offset);
            
            if (offset + payload_header.payload_length > data.size()) {
                throw std::runtime_error("Invalid payload length");
            }
            
            std::vector<uint8_t> payload_data(data.begin() + offset, 
                                            data.begin() + offset + payload_header.payload_length);
            
            message.addPayload(current_payload, payload_data);
            
            current_payload = payload_header.next_payload;
            offset += payload_header.payload_length;
        }
        
        return message;
    }

    const std::vector<uint8_t> getPayloadFromMessage(PayloadType type) const {
        for (const auto& p : payloads) {
            if (p.first == type) {
                // p.second chứa toàn bộ payload (bao gồm header 4 byte + dữ liệu nonce)
                if (p.second.size() <= 4) {
                    throw std::runtime_error("Invalid nonce payload size");
                }
                // Bỏ 4 byte header, lấy phần nonce data
                return std::vector<uint8_t>(p.second.begin() + 4, p.second.end());
            }
        }
        throw std::runtime_error("Nonce payload not found");
    }
};
