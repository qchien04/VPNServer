#include "common.h"
#include <vector>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "Transform.h"

struct Proposal {
    uint8_t proposal_num;
    uint8_t protocol_id;
    uint8_t spi_size;
    uint8_t num_transforms;
    std::vector<uint8_t> spi;
    std::vector<Transform> transforms;
    
    Proposal(uint8_t num, uint8_t protocol, uint8_t spi_sz) 
        : proposal_num(num), protocol_id(protocol), spi_size(spi_sz), num_transforms(0) {}
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.push_back(proposal_num);
        data.push_back(protocol_id);
        data.push_back(spi.size());
        data.push_back(static_cast<uint8_t>(transforms.size()));
        
        data.insert(data.end(), spi.begin(), spi.end());
        
        std::cout << "  SPI1 = 0x" << bytesToHex(spi) << "\n";

        for (const auto& transform : transforms) {
            std::vector<uint8_t> t_data = transform.serialize();
            data.insert(data.end(), t_data.begin(), t_data.end());
        }
        
        return data;
    }
    static std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }


    static Proposal deserialize(const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + 4 > data.size()) {
            throw std::runtime_error("Invalid Proposal: too short");
        }

        // Bắt đầu đọc nội dung proposal
        Proposal p(data[offset], data[offset + 1], data[offset + 2]);
        p.num_transforms = data[offset + 3];

        offset+=4;
        if (p.spi_size > 0) {
            p.spi.insert(p.spi.end(),
                        data.begin() + offset,
                        data.begin() + offset + p.spi_size);
            offset += p.spi_size;

            //std::cout << "  SPI2 = 0x" << bytesToHex(p.spi) << "\n";
        }
        //std::cout << "  num_transforms" << static_cast<int>(p.num_transforms) << "\n";
        // Parse transforms
        for (int i = 0; i < static_cast<int>(p.num_transforms); ++i) {
            Transform t = Transform::deserialize(data, offset);
            p.transforms.push_back(t);
        }
        return p;
    }

    
    void debugPrint(int indent = 0) const {
        std::string pad(indent, ' ');
        std::cout << pad << "Proposal:" << "\n";
        std::cout << pad << "  Proposal Num = " << (int)proposal_num << "\n";
        std::cout << pad << "  Protocol ID  = " << (int)protocol_id << "\n";
        std::cout << pad << "  SPI Size     = " << (int)spi_size << "\n";
        std::cout << pad << "  Num Transforms = " << (int)num_transforms << "\n";
        if (!spi.empty()) {
            std::cout << pad << "  SPI = 0x" << bytesToHex(spi) << "\n";
        }
        for (const auto& t : transforms) {
            t.debugPrint(indent + 2);
        }
    }

};
