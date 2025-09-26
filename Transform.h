#include "common.h"
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>

struct Transform {
    TransformType transform_type;
    uint8_t reserved;
    uint16_t transform_length;
    uint16_t transform_id;
    std::vector<uint8_t> attributes;
    
    Transform(TransformType type, uint16_t id) : transform_type(type), reserved(0), 
              transform_length(8), transform_id(id) {}

    void debugPrint(int indent = 0) const {
        std::string pad(indent, ' ');
        std::cout << pad << "Transform:" << "\n";
        std::cout << pad << "  Type = " << static_cast<int>(transform_type) << "\n";
        std::cout << pad << "  ID   = " << transform_id << "\n";
        std::cout << pad << "  Len  = " << transform_length << "\n";
        if (!attributes.empty()) {
            std::cout << pad << "  Attributes = 0x" << bytesToHex(attributes) << "\n";
        }
    }
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(transform_type));
        data.push_back(reserved);
        
        uint16_t len = 6 + attributes.size();
        uint16_t len_be = host_to_net16(len);
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&len_be), 
                   reinterpret_cast<const uint8_t*>(&len_be) + 2);
        
        uint16_t id_be = host_to_net16(transform_id);
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&id_be), 
                   reinterpret_cast<const uint8_t*>(&id_be) + 2);
        
        data.insert(data.end(), attributes.begin(), attributes.end());
        return data;
    }

    static Transform deserialize(const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + 8 > data.size()) {
            throw std::runtime_error("Invalid Transform: too short");
        }

        Transform t(static_cast<TransformType>(data[offset]), 0);
        t.reserved = data[offset + 1];

        uint16_t length = net_to_host16(*reinterpret_cast<const uint16_t*>(&data[offset + 2]));
        t.transform_length = length;

        if (offset + length > data.size()) {
            throw std::runtime_error("Invalid Transform length");
        }

        t.transform_id = net_to_host16(*reinterpret_cast<const uint16_t*>(&data[offset + 4]));

        // Attributes (nếu có)
        size_t attr_len = length - 6;
        if (attr_len > 0) {
            t.attributes.insert(t.attributes.end(),
                                data.begin() + offset + 8,
                                data.begin() + offset + length);
        }

        offset += length;
        //t.debugPrint();
        return t;
    }

    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }
};
