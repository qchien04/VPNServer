#pragma once
#include "common.h"
#include <vector>
#include <cstring>

struct PayloadHeader {
    PayloadType next_payload;
    uint8_t critical_flag;
    uint16_t payload_length;
    
    PayloadHeader() : next_payload(PayloadType::NO_NEXT_PAYLOAD), critical_flag(0), payload_length(4) {}
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(4);
        data[0] = static_cast<uint8_t>(next_payload);
        data[1] = critical_flag;
        uint16_t len_be = host_to_net16(payload_length);
        memcpy(data.data() + 2, &len_be, 2);
        return data;
    }
    
    static PayloadHeader deserialize(const std::vector<uint8_t>& data, size_t offset = 0) {
        if (data.size() < offset + 4) {
            throw std::runtime_error("Invalid payload header size");
        }
        
        PayloadHeader header;
        header.next_payload = static_cast<PayloadType>(data[offset]);
        header.critical_flag = data[offset + 1];
        header.payload_length = net_to_host16(*reinterpret_cast<const uint16_t*>(data.data() + offset + 2));
        return header;
    }
};
