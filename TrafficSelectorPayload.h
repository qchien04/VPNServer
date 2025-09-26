#include "common.h"
#include <vector>
#include "TrafficSelector.h"
#include <sstream>
#include "PayloadHeader.h"
#include <iomanip>

class TrafficSelectorPayload {
private:
    bool is_initiator;
    std::vector<std::vector<uint8_t>> traffic_selectors;
    
public:

    TrafficSelectorPayload(bool initiator) : is_initiator(initiator) {}
    
    std::vector<std::vector<uint8_t>> getRaw(){
        return traffic_selectors;
    }

    void addTrafficSelector(const TrafficSelector& ts) {

        std::vector<uint8_t> ts_data;
        ts_data.push_back(ts.ts_type);
        ts_data.push_back(ts.ip_protocol_id);
        
        
        uint16_t raw=ts.selector_length;
        // std::cout << "[DEBUG] selector_length = " << raw << "\n";
        // std::cout << "raw = 0x" << std::hex << raw << std::endl;
        uint8_t* b = reinterpret_cast<uint8_t*>(&raw);
        // std::cout << "raw[0] = 0x" << std::hex << (int)b[0] << std::endl;
        // std::cout << "raw[1] = 0x" << std::hex << (int)b[1] << std::endl;
        
        uint16_t len_be = host_to_net16(ts.selector_length);
        //std::cout<< "net len "<<len_be<<std::endl;

        uint8_t* p = reinterpret_cast<uint8_t*>(&len_be);
        // std::cout << "p[0] = 0x" << std::hex << (int)p[0] << std::endl;
        // std::cout << "p[1] = 0x" << std::hex << (int)p[1] << std::endl;

        uint16_t start_port_be = host_to_net16(ts.start_port);
        uint16_t end_port_be = host_to_net16(ts.end_port);
        
        ts_data.insert(ts_data.end(), reinterpret_cast<const uint8_t*>(&len_be), 
                      reinterpret_cast<const uint8_t*>(&len_be) + 2);

        // std::cout << "ts_data[cursor+2] = 0x" << std::hex << (int)ts_data[2] << std::endl;
        // std::cout << "ts_data[cursor+3] = 0x" << std::hex << (int)ts_data[3] << std::endl;

        ts_data.insert(ts_data.end(), reinterpret_cast<const uint8_t*>(&start_port_be), 
                      reinterpret_cast<const uint8_t*>(&start_port_be) + 2);
        ts_data.insert(ts_data.end(), reinterpret_cast<const uint8_t*>(&end_port_be), 
                      reinterpret_cast<const uint8_t*>(&end_port_be) + 2);
        
        ts_data.insert(ts_data.end(), ts.starting_address.begin(), ts.starting_address.end());
        ts_data.insert(ts_data.end(), ts.ending_address.begin(), ts.ending_address.end());
        
        traffic_selectors.push_back(ts_data);
    }
    
    std::vector<uint8_t> serialize() const {

        PayloadHeader header;
        header.next_payload = PayloadType::NO_NEXT_PAYLOAD;
        header.critical_flag = 0;
        
        std::vector<uint8_t> payload_data;
        payload_data.push_back(static_cast<uint8_t>(traffic_selectors.size()));
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        payload_data.push_back(0); // Reserved
        
        for (const auto& ts : traffic_selectors) {
            payload_data.insert(payload_data.end(), ts.begin(), ts.end());
        }
        
        header.payload_length = 4 + payload_data.size();
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), payload_data.begin(), payload_data.end());
        
        return result;
    }

    static TrafficSelectorPayload deserialize(const std::vector<uint8_t>& data, size_t offset, bool initiator) {
        if (offset + 8 > data.size()) {
            throw std::runtime_error("Invalid TS payload: too short");
        }

        // B1: Đọc header
        PayloadHeader header = PayloadHeader::deserialize(data, offset);

        if (header.payload_length < 8) {
            throw std::runtime_error("Invalid TS payload length");
        }
        if (offset + header.payload_length > data.size()) {
            throw std::runtime_error("TS payload length exceeds packet size");
        }

        // B2: Số lượng TS
        uint8_t num_ts = data[offset + 4];
        // offset+5..7 = reserved

        size_t cursor = offset + 8;
        TrafficSelectorPayload ts_payload(initiator);

        // B3: Lặp qua từng Traffic Selector
        for (int i = 0; i < num_ts; i++) {
            if (cursor + 8 > data.size()) {
                throw std::runtime_error("Invalid TS: too short for header");
            }

            TrafficSelector ts;
            ts.ts_type = data[cursor];
            ts.ip_protocol_id = data[cursor + 1];
            const uint16_t* len_ptr = reinterpret_cast<const uint16_t*>(&data[cursor + 2]);
            uint16_t raw_len = *len_ptr;

            ts.selector_length = net_to_host16(raw_len);

            //std::cout<<"lenght affter swap "<<std::dec << net_to_host16(raw_len) <<std::endl;

            ts.start_port = net_to_host16(*reinterpret_cast<const uint16_t*>(&data[cursor + 4]));
            ts.end_port = net_to_host16(*reinterpret_cast<const uint16_t*>(&data[cursor + 6]));

            

            if (cursor + ts.selector_length > offset + header.payload_length) {
                throw std::runtime_error("Invalid TS: selector length exceeds payload");
            }

            size_t addr_len = (ts.selector_length - 8) / 2;
            ts.starting_address.assign(data.begin() + cursor + 8, data.begin() + cursor + 8 + addr_len);
            ts.ending_address.assign(data.begin() + cursor + 8 + addr_len, data.begin() + cursor + 8 + 2 * addr_len);

            // serialize lại dạng vector<uint8_t> để giữ nhất quán
            std::vector<uint8_t> ts_data(data.begin() + cursor, data.begin() + cursor + ts.selector_length);
            ts_payload.traffic_selectors.push_back(ts_data);

            cursor += ts.selector_length;
        }

        return ts_payload;
    }

    static std::vector<TrafficSelector> toListTrafficSelector(const TrafficSelectorPayload& payload) {
        std::vector<TrafficSelector> result;

        for (const auto& ts_raw : payload.traffic_selectors) {
            if (ts_raw.size() < 8) {
                throw std::runtime_error("Invalid TS: too short");
            }

            TrafficSelector ts;
            ts.ts_type        = ts_raw[0];
            ts.ip_protocol_id = ts_raw[1];
            ts.selector_length = (ts_raw[2] << 8) | ts_raw[3];
            ts.start_port     = (ts_raw[4] << 8) | ts_raw[5];
            ts.end_port       = (ts_raw[6] << 8) | ts_raw[7];

            size_t addr_len = (ts.selector_length - 8) / 2;
            if (ts_raw.size() < 8 + 2 * addr_len) {
                throw std::runtime_error("Invalid TS: truncated address data");
            }

            ts.starting_address.assign(ts_raw.begin() + 8, ts_raw.begin() + 8 + addr_len);
            ts.ending_address.assign(ts_raw.begin() + 8 + addr_len, ts_raw.begin() + 8 + 2 * addr_len);

            result.push_back(ts);
        }

        return result;
    }

    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }

    static std::string ipToString(const std::vector<uint8_t>& addr) {
        std::ostringstream oss;
        if (addr.size() == 4) {
            // IPv4
            oss << (int)addr[0] << "."
                << (int)addr[1] << "."
                << (int)addr[2] << "."
                << (int)addr[3];
        } else if (addr.size() == 16) {
            // IPv6
            for (size_t i = 0; i < 16; i += 2) {
                uint16_t part = (addr[i] << 8) | addr[i+1];
                oss << std::hex << part;
                if (i < 14) oss << ":";
            }
        } else {
            // Unknown length
            return bytesToHex(addr);
        }
        return oss.str();
    }

    void debugPrint(int indent = 0) const {
        std::string pad(indent, ' ');
        std::cout << pad << (is_initiator ? "TSi Payload:" : "TSr Payload:") << "\n";

        for (size_t i = 0; i < traffic_selectors.size(); ++i) {
            const auto& ts_raw = traffic_selectors[i];
            if (ts_raw.size() < 8) {
                std::cout << pad << "  TS[" << i << "] Invalid (too short)\n";
                continue;
            }

            uint8_t ts_type       = ts_raw[0];
            uint8_t proto_id      = ts_raw[1];
            uint16_t length       = (ts_raw[2] << 8) | ts_raw[3];
            uint16_t start_port   = (ts_raw[4] << 8) | ts_raw[5];
            uint16_t end_port     = (ts_raw[6] << 8) | ts_raw[7];

            std::cout << pad << "  TS[" << i << "]\n";
            std::cout << pad << "    Type      = " << (int)ts_type << "\n";
            std::cout << pad << "    Proto ID  = " << (int)proto_id << "\n";
            std::cout << pad << "    Length    = " << (int)length << "\n";
            std::cout << pad << "    Ports     = " << (int)start_port << "-" << end_port << "\n";

            size_t addr_len = (length - 8) / 2;
            if (ts_raw.size() >= 8 + 2 * addr_len) {
                std::vector<uint8_t> start_addr(ts_raw.begin() + 8, ts_raw.begin() + 8 + addr_len);
                std::vector<uint8_t> end_addr(ts_raw.begin() + 8 + addr_len, ts_raw.begin() + 8 + 2 * addr_len);

                std::cout << pad << "    StartAddr = " << ipToString(start_addr) << "\n";
                std::cout << pad << "    EndAddr   = " << ipToString(end_addr) << "\n";
            } else {
                std::cout << pad << "    Addr info truncated!\n";
            }
        }
    }


};
