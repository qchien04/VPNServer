#include "common.h"
#include "Proposal.h"
#include "PayloadHeader.h"


class SAPayload {
private:
    std::vector<Proposal> proposals;

    
public:
    void addProposal(const Proposal& proposal) {
        proposals.push_back(proposal);
    }
    std::vector<Proposal> getProposals(){
        return proposals;
    }

    std::vector<uint8_t> serialize() const {
        PayloadHeader header;
        header.next_payload = PayloadType::NO_NEXT_PAYLOAD;
        header.critical_flag = 0;
        
        std::vector<uint8_t> payload_data;
        
        for (size_t i = 0; i < proposals.size(); ++i) {
            std::vector<uint8_t> prop_data = proposals[i].serialize();
            
            // Add proposal sub-header
            uint8_t last_proposal = (i == proposals.size() - 1) ? 0 : 2;
            payload_data.push_back(last_proposal);
            payload_data.push_back(0); // reserved
            
            uint16_t prop_len = prop_data.size() + 4;
            uint16_t prop_len_be = host_to_net16(prop_len);

            payload_data.insert(payload_data.end(), 
                              reinterpret_cast<const uint8_t*>(&prop_len_be), 
                              reinterpret_cast<const uint8_t*>(&prop_len_be) + 2);
            
            payload_data.insert(payload_data.end(), prop_data.begin(), prop_data.end());
        }
        
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
        
        for (size_t i = 0; i < proposals.size(); ++i) {
            std::vector<uint8_t> prop_data = proposals[i].serialize();
            std::cout << "propdata size" << prop_data.size() << "\n";

            // Add proposal sub-header
            uint8_t last_proposal = (i == proposals.size() - 1) ? 0 : 2;
            payload_data.push_back(last_proposal);
            payload_data.push_back(0); // reserved
            
            uint16_t prop_len = prop_data.size() + 4;
            uint16_t prop_len_be = host_to_net16(prop_len);

                        

            payload_data.insert(payload_data.end(), 
                              reinterpret_cast<const uint8_t*>(&prop_len_be), 
                              reinterpret_cast<const uint8_t*>(&prop_len_be) + 2);
            
            payload_data.insert(payload_data.end(), prop_data.begin(), prop_data.end());
        }
        std::cout << "payload_data1 size" << payload_data.size() << "\n";
        header.payload_length = 4 + payload_data.size();
        std::cout << "payload_length " << static_cast<int>(header.payload_length) << "\n";
        std::vector<uint8_t> result = header.serialize();
        result.insert(result.end(), payload_data.begin(), payload_data.end());
        
        return result;
    }
    
    static SAPayload createDefaultSA() {
        SAPayload sa;
        
        // Create a default IKE proposal
        Proposal ike_proposal(1, static_cast<uint8_t>(ProtocolID::IKE), 0);
        ike_proposal.transforms.push_back(Transform(TransformType::ENCR, static_cast<uint16_t>(EncryptionAlgorithm::AES_CBC_256)));
        ike_proposal.transforms.push_back(Transform(TransformType::PRF, static_cast<uint16_t>(PRFAlgorithm::PRF_HMAC_SHA256)));
        ike_proposal.transforms.push_back(Transform(TransformType::INTEG, static_cast<uint16_t>(IntegrityAlgorithm::AUTH_HMAC_SHA256_128)));
        ike_proposal.transforms.push_back(Transform(TransformType::DH, static_cast<uint16_t>(DHGroup::MODP_2048)));
        ike_proposal.num_transforms = ike_proposal.transforms.size();
        
        sa.addProposal(ike_proposal);
        return sa;
    }

    std::string static bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }

    static SAPayload createChildSAProposal(uint32_t inbound_spi) {
        SAPayload sa;
        
        // Create ESP proposal
        Proposal esp_proposal(1, static_cast<uint8_t>(ProtocolID::ESP), 4);
        // Add SPI
        uint32_t spi_be = host_to_net32(inbound_spi);
        
        esp_proposal.spi.assign(reinterpret_cast<uint8_t*>(&spi_be),
                               reinterpret_cast<uint8_t*>(&spi_be) + 4);
        // Add transforms
        esp_proposal.transforms.push_back(Transform(TransformType::ENCR, 
            static_cast<uint16_t>(EncryptionAlgorithm::AES_CBC_256)));
        esp_proposal.transforms.push_back(Transform(TransformType::INTEG, 
            static_cast<uint16_t>(IntegrityAlgorithm::AUTH_HMAC_SHA256_128)));
        //esp_proposal.transforms.push_back(Transform(TransformType::ESN, 0)); // No ESN
        
        esp_proposal.num_transforms = esp_proposal.transforms.size();
        
        sa.addProposal(esp_proposal);
        return sa;
    }

    static SAPayload deserialize(const std::vector<uint8_t>& data, size_t offset) {
        if (offset + 4 > data.size()) {
            throw std::runtime_error("Invalid SA payload: too short");
        }

        PayloadHeader header = PayloadHeader::deserialize(data, offset);
        if (offset + header.payload_length > data.size()) {
            throw std::runtime_error("SA payload length exceeds packet size");
        }

        SAPayload sa;
        size_t inner_off = offset + 4; // skip payload header
        //std::cout << "00000000001 0x" << std::hex << static_cast<int>(header.payload_length) << "\n";
        while (inner_off < offset + header.payload_length) {

            uint8_t last_proposal = data[inner_off]; // 0 = last, 2 = more
            uint8_t reserved = data[inner_off + 1];
            uint16_t prop_len = net_to_host16(*reinterpret_cast<const uint16_t*>(&data[inner_off + 2]));

            inner_off+=4;
            Proposal p = Proposal::deserialize(data, inner_off);

            //std::cout<<"inner off"<<std::hex << static_cast<int>(inner_off) << "\n";
            sa.addProposal(p);

            if (last_proposal == 0) break;
        }

        return sa;
    }

    void debugPrint(int indent = 0) const {
        std::string pad(indent, ' ');
        std::cout << pad << "=== Security Association Payload ===\n";
        for (const auto& p : proposals) {
            p.debugPrint(indent + 2);
        }
        std::cout << pad << "===================================\n";
    }

};
