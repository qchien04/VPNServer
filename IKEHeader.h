#include "common.h"
#include <vector>
#include <string>
#include <cstring>

struct IKEHeader {
    uint64_t initiator_spi;
    uint64_t responder_spi;
    PayloadType next_payload;
    uint8_t version;
    IKEMessageType exchange_type;
    uint8_t flags;
    uint32_t message_id;
    uint32_t length;
    
    IKEHeader() : initiator_spi(0), responder_spi(0), next_payload(PayloadType::NO_NEXT_PAYLOAD),
                  version(0x20), exchange_type(IKEMessageType::IKE_SA_INIT), flags(0), 
                  message_id(0), length(0) {}
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data(28);
        size_t offset = 0;
        
        // SPIs in network byte order
        uint64_t ispi_be = htobe64(initiator_spi);
        uint64_t rspi_be = htobe64(responder_spi);
        memcpy(data.data() + offset, &ispi_be, 8); offset += 8;
        memcpy(data.data() + offset, &rspi_be, 8); offset += 8;
        
        data[offset++] = static_cast<uint8_t>(next_payload);
        data[offset++] = version;
        data[offset++] = static_cast<uint8_t>(exchange_type);
        data[offset++] = flags;
        
        uint32_t msg_id_be = host_to_net32(message_id);
        uint32_t length_be = host_to_net32(length);
        memcpy(data.data() + offset, &msg_id_be, 4); offset += 4;
        memcpy(data.data() + offset, &length_be, 4);
        
        return data;
    }
    
    static IKEHeader deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 28) {
            throw std::runtime_error("Invalid IKE header size");
        }
        
        IKEHeader header;
        size_t offset = 0;
        
        header.initiator_spi = be64toh(*reinterpret_cast<const uint64_t*>(data.data() + offset)); offset += 8;
        header.responder_spi = be64toh(*reinterpret_cast<const uint64_t*>(data.data() + offset)); offset += 8;
        header.next_payload = static_cast<PayloadType>(data[offset++]);
        header.version = data[offset++];
        header.exchange_type = static_cast<IKEMessageType>(data[offset++]);
        header.flags = data[offset++];
        header.message_id = net_to_host32(*reinterpret_cast<const uint32_t*>(data.data() + offset)); offset += 4;
        header.length = net_to_host32(*reinterpret_cast<const uint32_t*>(data.data() + offset));
        
        return header;
    }
};
