#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <memory>
#include <random>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>

// Network headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

//g++ -std=c++14 -O2 -Wall -Wextra -o ikev2_network ikev2_network.cpp -lssl -lcrypto -lpthread

#include "IKESA.h"
#include "KEPayload.h"
#include "IKEMessage.h"
#include "SAPayload.h"
#include "NoncePayload.h"
#include "IdentityPayload.h"
#include "AuthPayload.h"
#include "TrafficSelectorPayload.h"

// Network wrapper for IKEv2 messages
class NetworkMessage {
public:
    struct sockaddr_in peer_addr;
    std::vector<uint8_t> data;
    size_t data_length;
    
    NetworkMessage() : data_length(0) {
        memset(&peer_addr, 0, sizeof(peer_addr));
    }
    
    NetworkMessage(const std::vector<uint8_t>& msg_data, const struct sockaddr_in& addr) 
        : peer_addr(addr), data(msg_data), data_length(msg_data.size()) {}
};

// Network IKEv2 Protocol Implementation
class IKEv2NetworkProtocol {
private:
    std::unique_ptr<IKESA> sa;
    std::unique_ptr<KEPayload> ke_payload;
    bool is_initiator;
    std::vector<uint8_t> ni, nr; // Nonces
    std::vector<uint8_t> sa_init_request_data;
    std::vector<uint8_t> sa_init_response_data;
    std::string preshared_key;
    
    // Network components
    int socket_fd;
    struct sockaddr_in local_addr;
    struct sockaddr_in peer_addr;
    uint16_t local_port;
    bool socket_initialized;
    
    // Message tracking
    uint32_t message_id_in;
    uint32_t message_id_out;
    
    enum class ProtocolState {
        IDLE,
        SA_INIT_SENT,
        SA_INIT_RECEIVED,
        AUTH_SENT,
        AUTH_RECEIVED,
        ESTABLISHED,
        ERROR_STATE
    };
    
    ProtocolState current_state;

public:
    IKEv2NetworkProtocol(bool initiator, const std::string& psk = "defaultpsk", uint16_t port = 500) 
        : is_initiator(initiator), preshared_key(psk), local_port(port), 
          socket_initialized(false), current_state(ProtocolState::IDLE),
          message_id_in(0), message_id_out(0) {
        sa = std::make_unique<IKESA>(initiator);
        initializeSocket();
    }
    
    ~IKEv2NetworkProtocol() {
        if (socket_initialized && socket_fd >= 0) {
            close(socket_fd);
        }
    }
    
    // Network initialization
    bool initializeSocket() {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
            return false;
        }
        
        // Set socket to non-blocking
        int flags = fcntl(socket_fd, F_GETFL, 0);
        if (flags < 0) {
            std::cerr << "Failed to get socket flags" << std::endl;
            close(socket_fd);
            return false;
        }
        
        if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            std::cerr << "Failed to set socket non-blocking" << std::endl;
            close(socket_fd);
            return false;
        }
        
        // Enable address reuse
        int opt = 1;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "Failed to set SO_REUSEADDR" << std::endl;
            close(socket_fd);
            return false;
        }
        
        // Bind to local address
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = htons(local_port);
        
        if (bind(socket_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
            std::cerr << "Failed to bind socket to port " << local_port 
                      << ": " << strerror(errno) << std::endl;
            close(socket_fd);
            return false;
        }
        
        socket_initialized = true;
        std::cout << "Socket initialized on port " << local_port << std::endl;
        return true;
    }
    
    // Set peer address for initiator
    bool setPeerAddress(const std::string& peer_ip, uint16_t peer_port = 500) {
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(peer_port);
        
        if (inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr) <= 0) {
            std::cerr << "Invalid peer IP address: " << peer_ip << std::endl;
            return false;
        }
        
        std::cout << "Peer address set to " << peer_ip << ":" << peer_port << std::endl;
        return true;
    }
    
    // Send network message
    bool sendMessage(const std::vector<uint8_t>& data, const struct sockaddr_in& dest_addr) {
        if (!socket_initialized) {
            std::cerr << "Socket not initialized" << std::endl;
            return false;
        }
        
        ssize_t bytes_sent = sendto(socket_fd, data.data(), data.size(), 0,
                                   (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        
        if (bytes_sent < 0) {
            std::cerr << "Failed to send message: " << strerror(errno) << std::endl;
            return false;
        }
        
        if ((size_t)bytes_sent != data.size()) {
            std::cerr << "Partial send: " << bytes_sent << " of " << data.size() << " bytes" << std::endl;
            return false;
        }
        
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &dest_addr.sin_addr, addr_str, INET_ADDRSTRLEN);
        std::cout << "Sent " << bytes_sent << " bytes to " << addr_str 
                  << ":" << ntohs(dest_addr.sin_port) << std::endl;
        
        return true;
    }
    
    // Receive network message with timeout
    NetworkMessage receiveMessage(int timeout_ms = 5000) {
        NetworkMessage net_msg;
        
        if (!socket_initialized) {
            std::cerr << "Socket not initialized" << std::endl;
            return net_msg;
        }
        
        // Use poll for timeout
        struct pollfd pfd;
        pfd.fd = socket_fd;
        pfd.events = POLLIN;
        
        int poll_result = poll(&pfd, 1, timeout_ms);
        if (poll_result < 0) {
            std::cerr << "Poll error: " << strerror(errno) << std::endl;
            return net_msg;
        }
        
        if (poll_result == 0) {
            std::cerr << "Receive timeout after " << timeout_ms << "ms" << std::endl;
            return net_msg;
        }
        
        // Receive data
        uint8_t buffer[65536]; // Max UDP packet size
        socklen_t addr_len = sizeof(net_msg.peer_addr);
        
        ssize_t bytes_received = recvfrom(socket_fd, buffer, sizeof(buffer), 0,
                                         (struct sockaddr*)&net_msg.peer_addr, &addr_len);
        
        if (bytes_received < 0) {
            std::cerr << "Failed to receive message: " << strerror(errno) << std::endl;
            return net_msg;
        }
        
        net_msg.data.assign(buffer, buffer + bytes_received);
        net_msg.data_length = bytes_received;
        
        char addr_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net_msg.peer_addr.sin_addr, addr_str, INET_ADDRSTRLEN);
        std::cout << "Received " << bytes_received << " bytes from " << addr_str 
                  << ":" << ntohs(net_msg.peer_addr.sin_port) << std::endl;
        
        return net_msg;
    }
    
    // Helper functions from original implementation
    std::string bytesToHex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        return oss.str();
    }
    
    IKESA* getSa() { return sa.get(); }
    KEPayload* getKePayload() { return ke_payload.get(); }
    std::vector<uint8_t> getNi() { return ni; }
    std::vector<uint8_t> getNr() { return nr; }
    
    // Network-enabled protocol methods
    
    // Initiator: Start IKE exchange
    bool initiateIKEExchange(const std::string& peer_ip, uint16_t peer_port = 500) {
        if (!is_initiator) {
            std::cerr << "Not an initiator" << std::endl;
            return false;
        }
        
        if (!setPeerAddress(peer_ip, peer_port)) {
            return false;
        }
        
        std::cout << "\n=== Starting IKE_SA_INIT Exchange (Initiator) ===\n";
        
        // Create and send SA_INIT request
        IKEMessage sa_init_req = createSAInitRequest();
        std::vector<uint8_t> req_data = sa_init_req.serialize();
        
        if (!sendMessage(req_data, peer_addr)) {
            current_state = ProtocolState::ERROR_STATE;
            return false;
        }
        
        current_state = ProtocolState::SA_INIT_SENT;
        std::cout << "SA_INIT request sent, waiting for response...\n";
        
        // Wait for response
        NetworkMessage response = receiveMessage(10000); // 10 second timeout
        if (response.data.empty()) {
            std::cerr << "No response received for SA_INIT" << std::endl;
            current_state = ProtocolState::ERROR_STATE;
            return false;
        }
        
        // Process response
        try {
            IKEMessage sa_init_resp = IKEMessage::deserialize(response.data);
            if (!processSAInitResponse(sa_init_resp)) {
                current_state = ProtocolState::ERROR_STATE;
                return false;
            }
            
            // Update peer address from response
            peer_addr = response.peer_addr;
            current_state = ProtocolState::SA_INIT_RECEIVED;
            std::cout << "SA_INIT exchange completed successfully\n";
            
        } catch (const std::exception& e) {
            std::cerr << "Failed to process SA_INIT response: " << e.what() << std::endl;
            current_state = ProtocolState::ERROR_STATE;
            return false;
        }
        
        // Continue with AUTH exchange
        return performAuthExchange();
    }
    
    // Responder: Listen and handle incoming connections
    bool listenAndRespond() {
        if (is_initiator) {
            std::cerr << "Cannot listen as initiator" << std::endl;
            return false;
        }
        
        std::cout << "\n=== Listening for IKE connections ===\n";
        std::cout << "Waiting for SA_INIT request on port " << local_port << "...\n";
        
        while (true) {
            NetworkMessage request = receiveMessage(-1); // Block indefinitely
            if (request.data.empty()) {
                continue;
            }
            
            try {
                IKEMessage ike_msg = IKEMessage::deserialize(request.data);
                
                if (ike_msg.getHeader().exchange_type == IKEMessageType::IKE_SA_INIT &&
                    (ike_msg.getHeader().flags & INITIATOR_FLAG)) {
                    
                    std::cout << "Received SA_INIT request\n";
                    
                    // Process and respond
                    IKEMessage sa_init_resp = createSAInitResponse(ike_msg);
                    std::vector<uint8_t> resp_data = sa_init_resp.serialize();
                    
                    if (!sendMessage(resp_data, request.peer_addr)) {
                        std::cerr << "Failed to send SA_INIT response" << std::endl;
                        continue;
                    }
                    
                    peer_addr = request.peer_addr;
                    current_state = ProtocolState::SA_INIT_RECEIVED;
                    std::cout << "SA_INIT response sent\n";
                    
                    // Handle AUTH exchange
                    if (!handleAuthExchange()) {
                        std::cerr << "AUTH exchange failed" << std::endl;
                        current_state = ProtocolState::ERROR_STATE;
                        continue;
                    }
                    
                    std::cout << "IKE connection established successfully!\n";
                    return true;
                }
                
            } catch (const std::exception& e) {
                std::cerr << "Error processing message: " << e.what() << std::endl;
            }
        }
        
        return false;
    }
    
private:
    // Perform AUTH exchange (Initiator)
    bool performAuthExchange() {
        std::cout << "\n=== Starting IKE_AUTH Exchange (Initiator) ===\n";
        
        // Create and send AUTH request
        IKEMessage auth_req = createAuthRequest();
        std::vector<uint8_t> req_data = auth_req.serialize();
        
        if (!sendMessage(req_data, peer_addr)) {
            current_state = ProtocolState::ERROR_STATE;
            return false;
        }
        
        current_state = ProtocolState::AUTH_SENT;
        std::cout << "AUTH request sent, waiting for response...\n";
        
        // Wait for AUTH response
        NetworkMessage response = receiveMessage(10000);
        if (response.data.empty()) {
            std::cerr << "No response received for AUTH" << std::endl;
            current_state = ProtocolState::ERROR_STATE;
            return false;
        }
        
        try {
            IKEMessage auth_resp = IKEMessage::deserialize(response.data);
            if (auth_resp.getHeader().exchange_type == IKEMessageType::IKE_AUTH &&
                (auth_resp.getHeader().flags & RESPONSE_FLAG)) {
                
                parseAuthResponseRaw(auth_resp);
                
                // Derive Child SA keys
                sa->getFirstChildSA()->deriveKeys(sa->getSK_d(), ni, nr);
                
                current_state = ProtocolState::ESTABLISHED;
                std::cout << "IKE connection established successfully!\n";
                return true;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to process AUTH response: " << e.what() << std::endl;
        }
        
        current_state = ProtocolState::ERROR_STATE;
        return false;
    }
    
    // Handle AUTH exchange (Responder)
    bool handleAuthExchange() {
        std::cout << "\n=== Handling IKE_AUTH Exchange (Responder) ===\n";
        
        std::cout << "Waiting for AUTH request...\n";
        NetworkMessage request = receiveMessage(10000);
        if (request.data.empty()) {
            std::cerr << "No AUTH request received" << std::endl;
            return false;
        }
        
        try {
            IKEMessage auth_req = IKEMessage::deserialize(request.data);
            if (auth_req.getHeader().exchange_type == IKEMessageType::IKE_AUTH &&
                (auth_req.getHeader().flags & INITIATOR_FLAG)) {
                
                std::cout << "Received AUTH request\n";
                
                // Process request
                parseAuthRequestRaw(auth_req);
                
                // Create and send response
                IKEMessage auth_resp = createAuthResponse(auth_req);
                std::vector<uint8_t> resp_data = auth_resp.serialize();
                
                if (!sendMessage(resp_data, request.peer_addr)) {
                    std::cerr << "Failed to send AUTH response" << std::endl;
                    return false;
                }
                
                // Derive Child SA keys
                sa->getFirstChildSA()->deriveKeys(sa->getSK_d(), ni, nr);
                
                current_state = ProtocolState::ESTABLISHED;
                std::cout << "AUTH response sent\n";
                return true;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to process AUTH request: " << e.what() << std::endl;
        }
        
        return false;
    }
    
    // Original IKEv2 protocol methods (adapted for network use)
    IKEMessage createSAInitRequest() {
        IKEMessage msg(IKEMessageType::IKE_SA_INIT);
        
        IKEHeader header;
        header.initiator_spi = sa->getInitiatorSPI();
        header.responder_spi = 0;
        header.flags = INITIATOR_FLAG;
        header.message_id = 0;
        header.exchange_type = IKEMessageType::IKE_SA_INIT;
        msg.setHeader(header);
        
        SAPayload sa_payload = SAPayload::createDefaultSA();
        std::vector<uint8_t> sa_data = sa_payload.serialize();
        msg.addPayload(PayloadType::SA, sa_data);
        
        ke_payload = std::make_unique<KEPayload>(DHGroup::MODP_2048);
        std::vector<uint8_t> ke_data = ke_payload->serialize();
        msg.addPayload(PayloadType::KE, ke_data);
        
        NoncePayload nonce_payload;
        ni = nonce_payload.getNonce();
        std::vector<uint8_t> nonce_data = nonce_payload.serialize();
        msg.addPayload(PayloadType::Ni, nonce_data);
        
        sa_init_request_data = msg.serialize();
        return msg;
    }
    
    IKEMessage createSAInitResponse(const IKEMessage& request) {
        uint64_t resp_spi;
        sa->generateSPI(resp_spi);
        sa->setResponderSPI(resp_spi);
        sa->setInitiatorSPI(request.getHeader().initiator_spi);
        ni = request.getPayloadFromMessage(PayloadType::Ni);
        sa_init_request_data = request.serialize();
        
        IKEMessage msg(IKEMessageType::IKE_SA_INIT);
        
        IKEHeader header;
        header.initiator_spi = request.getHeader().initiator_spi;
        header.exchange_type = IKEMessageType::IKE_SA_INIT;
        header.responder_spi = sa->getResponderSPI();
        header.flags = RESPONSE_FLAG;
        header.message_id = 0;
        msg.setHeader(header);
        
        SAPayload sa_payload = SAPayload::createDefaultSA();
        std::vector<uint8_t> sa_data = sa_payload.serialize();
        msg.addPayload(PayloadType::SA, sa_data);
        
        ke_payload = std::make_unique<KEPayload>(DHGroup::MODP_2048);
        std::vector<uint8_t> ke_data = ke_payload->serialize();
        msg.addPayload(PayloadType::KE, ke_data);
        
        NoncePayload nonce_payload;
        nr = nonce_payload.getNonce();
        std::vector<uint8_t> nonce_data = nonce_payload.serialize();
        msg.addPayload(PayloadType::Nr, nonce_data);
        
        try {
            std::vector<uint8_t> ke_body = request.getPayloadFromMessage(PayloadType::KE);
            KEPayload peer_ke = KEPayload::deserialize(ke_body);
            
            std::vector<uint8_t> dh_shared_secret = ke_payload->computeSharedSecret(peer_ke.getPeerPublicKey());
            ke_payload->setPeerKey(peer_ke.getPeerPublicKey());
            
            sa->deriveKeys(dh_shared_secret, ni, nr);
        } catch (const std::exception& e) {
            std::cerr << "Error processing SA_INIT response: " << e.what() << std::endl;
        }
        
        sa_init_response_data = msg.serialize();
        return msg;
    }
    
    bool processSAInitResponse(const IKEMessage& response) {
        sa_init_response_data = response.serialize();
        sa->setResponderSPI(response.getHeader().responder_spi);
        nr = response.getPayloadFromMessage(PayloadType::Nr);
        
        try {
            std::vector<uint8_t> ke_body = response.getPayloadFromMessage(PayloadType::KE);
            KEPayload peer_ke = KEPayload::deserialize(ke_body);
            
            ke_payload->setPeerKey(peer_ke.getPeerPublicKey());
            std::vector<uint8_t> dh_shared_secret = ke_payload->computeSharedSecret(peer_ke.getPeerPublicKey());
            
            sa->deriveKeys(dh_shared_secret, ni, nr);
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error processing SA_INIT response: " << e.what() << std::endl;
            return false;
        }
    }
    
    // Auth request/response methods (simplified versions of original)
    IKEMessage createAuthRequest() {
        sa->createFirstChildSA();
        IKEMessage msg(IKEMessageType::IKE_AUTH);
        
        IKEHeader header;
        header.initiator_spi = sa->getInitiatorSPI();
        header.responder_spi = sa->getResponderSPI();
        header.flags = INITIATOR_FLAG;
        header.message_id = 1;
        header.exchange_type = IKEMessageType::IKE_AUTH;
        msg.setHeader(header);
        
        std::vector<uint8_t> inner_plain;
        
        // IDi
        std::string identity = "initiator@example.com";
        std::vector<uint8_t> id_data(identity.begin(), identity.end());
        IdentityPayload idi(IdentityPayload::ID_RFC822_ADDR, id_data);
        std::vector<uint8_t> idi_serial = idi.serialize(PayloadType::AUTH);
        inner_plain.insert(inner_plain.end(), idi_serial.begin(), idi_serial.end());
        
        // AUTH
        std::vector<uint8_t> psk_vec(preshared_key.begin(), preshared_key.end());
        std::vector<uint8_t> sa_init_octets = sa_init_request_data;
        sa_init_octets.insert(sa_init_octets.end(), sa_init_response_data.begin(), sa_init_response_data.end());
        
        std::vector<uint8_t> auth_data = AuthPayload::calculatePSKAuth(
            psk_vec, sa->getSK_pi(), idi_serial, sa_init_octets);
        AuthPayload auth_payload(AuthPayload::SHARED_KEY_MESSAGE_INTEGRITY_CODE, auth_data);
        
        std::vector<uint8_t> auth_serial = auth_payload.serialize(PayloadType::SA);
        inner_plain.insert(inner_plain.end(), auth_serial.begin(), auth_serial.end());
        
        // Child SA
        SAPayload child_sa = SAPayload::createChildSAProposal(sa->getFirstChildSA()->getInboundSPI());
        std::vector<uint8_t> child_sa_serial = child_sa.serialize(PayloadType::TSi);
        inner_plain.insert(inner_plain.end(), child_sa_serial.begin(), child_sa_serial.end());
        
        // TSi
        TrafficSelectorPayload tsi(true);
        TrafficSelector ts_init;
        ts_init.ts_type = 7;
        ts_init.ip_protocol_id = 0;
        ts_init.selector_length = 16;
        ts_init.start_port = 100;
        ts_init.end_port = 65535;
        ts_init.starting_address = {192,168,1,1};
        ts_init.ending_address  = {192,168,1,255};
        tsi.addTrafficSelector(ts_init);
        std::vector<uint8_t> tsi_serial = tsi.serialize();
        if (!tsi_serial.empty()) tsi_serial[0] = static_cast<uint8_t>(PayloadType::TSr);
        inner_plain.insert(inner_plain.end(), tsi_serial.begin(), tsi_serial.end());
        
        // TSr
        TrafficSelectorPayload tsr(false);
        TrafficSelector ts_resp;
        ts_resp.ts_type = 7;
        ts_resp.ip_protocol_id = 0;
        ts_resp.selector_length = 16;
        ts_resp.start_port = 100;
        ts_resp.end_port = 65535;
        ts_resp.starting_address = {192,168,2,1};
        ts_resp.ending_address  = {192,168,2,255};
        tsr.addTrafficSelector(ts_resp);
        std::vector<uint8_t> tsr_serial = tsr.serialize();
        if (!tsr_serial.empty()) tsr_serial[0] = static_cast<uint8_t>(PayloadType::NO_NEXT_PAYLOAD);
        inner_plain.insert(inner_plain.end(), tsr_serial.begin(), tsr_serial.end());
        
        // Encrypt
        std::vector<uint8_t> encrypted_inner = sa->encryptPayload(inner_plain);
        
        PayloadHeader sk_ph;
        sk_ph.next_payload = PayloadType::IDi;
        sk_ph.critical_flag = 0;
        sk_ph.payload_length = 4 + encrypted_inner.size();
        std::vector<uint8_t> sk_payload = sk_ph.serialize();
        sk_payload.insert(sk_payload.end(), encrypted_inner.begin(), encrypted_inner.end());
        
        msg.addPayload(PayloadType::SK, sk_payload);
        return msg;
    }
    
    IKEMessage createAuthResponse(const IKEMessage& request) {
        IKEMessage msg(IKEMessageType::IKE_AUTH);
        
        IKEHeader header;
        header.initiator_spi = sa->getInitiatorSPI();
        header.responder_spi = sa->getResponderSPI();
        header.flags = RESPONSE_FLAG;
        header.message_id = 1;
        header.exchange_type = IKEMessageType::IKE_AUTH;
        msg.setHeader(header);
        
        std::vector<uint8_t> inner_plain;
        
        // IDr
        std::string responder_identity = "responder@example.com";
        std::vector<uint8_t> idr_data(responder_identity.begin(), responder_identity.end());
        IdentityPayload idr(IdentityPayload::ID_RFC822_ADDR, idr_data);
        std::vector<uint8_t> idr_serial = idr.serialize(PayloadType::AUTH);
        inner_plain.insert(inner_plain.end(), idr_serial.begin(), idr_serial.end());
        
        // AUTH
        std::vector<uint8_t> psk_vec(preshared_key.begin(), preshared_key.end());
        std::vector<uint8_t> sa_init_octets = sa_init_request_data;
        sa_init_octets.insert(sa_init_octets.end(), sa_init_response_data.begin(), sa_init_response_data.end());
        
        std::vector<uint8_t> auth_data = AuthPayload::calculatePSKAuth(
            psk_vec, sa->getSK_pr(), idr_serial, sa_init_octets);
        AuthPayload auth_payload(AuthPayload::SHARED_KEY_MESSAGE_INTEGRITY_CODE, auth_data);
        std::vector<uint8_t> auth_serial = auth_payload.serialize(PayloadType::SA);
        inner_plain.insert(inner_plain.end(), auth_serial.begin(), auth_serial.end());
        
        // Child SA
        SAPayload chosen_sa = SAPayload::createChildSAProposal(sa->getFirstChildSA()->getInboundSPI());
        std::vector<uint8_t> sa_serial = chosen_sa.serialize();
        if (!sa_serial.empty()) sa_serial[0] = static_cast<uint8_t>(PayloadType::TSi);
        inner_plain.insert(inner_plain.end(), sa_serial.begin(), sa_serial.end());
        
        // TSi
        TrafficSelectorPayload tsi(true);
        TrafficSelector ts_init;
        ts_init.ts_type = 7;
        ts_init.ip_protocol_id = 0;
        ts_init.selector_length = 16;
        ts_init.start_port = 0;
        ts_init.end_port = 65535;
        ts_init.starting_address = {192,168,1,1};
        ts_init.ending_address  = {192,168,1,255};
        tsi.addTrafficSelector(ts_init);
        std::vector<uint8_t> tsi_serial = tsi.serialize();
        if (!tsi_serial.empty()) tsi_serial[0] = static_cast<uint8_t>(PayloadType::TSr);
        inner_plain.insert(inner_plain.end(), tsi_serial.begin(), tsi_serial.end());
        
        // TSr
        TrafficSelectorPayload tsr(false);
        TrafficSelector ts_resp;
        ts_resp.ts_type = 7;
        ts_resp.ip_protocol_id = 0;
        ts_resp.selector_length = 16;
        ts_resp.start_port = 0;
        ts_resp.end_port = 65535;
        ts_resp.starting_address = {192,168,2,1};
        ts_resp.ending_address  = {192,168,2,255};
        tsr.addTrafficSelector(ts_resp);
        std::vector<uint8_t> tsr_serial = tsr.serialize();
        if (!tsr_serial.empty()) tsr_serial[0] = static_cast<uint8_t>(PayloadType::NO_NEXT_PAYLOAD);
        inner_plain.insert(inner_plain.end(), tsr_serial.begin(), tsr_serial.end());
        
        // Encrypt
        std::vector<uint8_t> encrypted_inner = sa->encryptPayload(inner_plain);
        
        PayloadHeader sk_ph;
        sk_ph.next_payload = PayloadType::IDr;
        sk_ph.payload_length = 4 + encrypted_inner.size();
        std::vector<uint8_t> sk_payload = sk_ph.serialize();
        sk_payload.insert(sk_payload.end(), encrypted_inner.begin(), encrypted_inner.end());
        
        msg.addPayload(PayloadType::SK, sk_payload);
        return msg;
    }
    
    void parseAuthRequestRaw(IKEMessage request) {
        sa->createFirstChildSA();
        
        std::vector<uint8_t> payload_data = request.getPayloadFromMessage(PayloadType::SK);
        std::vector<uint8_t> decrypted_inner = sa->decryptPayload(payload_data);
        
        size_t inner_off = 0;
        PayloadHeader inner_hdr;
        
        // Parse IDi
        IdentityPayload idi = IdentityPayload::deserialize(decrypted_inner, inner_off);
        std::cout << "[Responder] Got IDi payload" << std::endl;
        
        inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
        inner_off += inner_hdr.payload_length;
        
        // Parse AUTH
        if (inner_hdr.next_payload == PayloadType::AUTH) {
            AuthPayload auth = AuthPayload::deserialize(decrypted_inner, inner_off);
            std::cout << "[Responder] Got AUTH payload" << std::endl;
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
        }
        
        // Parse SA
        if (inner_hdr.next_payload == PayloadType::SA) {
            SAPayload sa_payload = SAPayload::deserialize(decrypted_inner, inner_off);
            sa->getFirstChildSA()->setSpiOutbound(net_to_host32(*reinterpret_cast<const uint32_t*>(sa_payload.getProposals()[0].spi.data())));
            std::cout << "[Responder] Got Child SA payload" << std::endl;
            sa_payload.debugPrint();
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
        }
        
        // Parse TSi
        if (inner_hdr.next_payload == PayloadType::TSi) {
            TrafficSelectorPayload tsi = TrafficSelectorPayload::deserialize(decrypted_inner, inner_off, true);
            std::cout << "[Responder] Got TSi payload" << std::endl;
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
            std::vector<TrafficSelector> v1 = TrafficSelectorPayload::toListTrafficSelector(tsi);
            sa->getFirstChildSA()->setTrafficSelectorsI(v1);
        }
        
        // Parse TSr
        if (inner_hdr.next_payload == PayloadType::TSr) {
            TrafficSelectorPayload tsr = TrafficSelectorPayload::deserialize(decrypted_inner, inner_off, false);
            std::cout << "[Responder] Got TSr payload" << std::endl;
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
            std::vector<TrafficSelector> v2 = TrafficSelectorPayload::toListTrafficSelector(tsr);
            sa->getFirstChildSA()->setTrafficSelectorsR(v2);
        }
        
        std::cout << "Finished parsing IKE_AUTH request." << std::endl;
        std::cout << sa->getFirstChildSA()->toString();
    }
    
    void parseAuthResponseRaw(IKEMessage request) {
        std::vector<uint8_t> payload_data = request.getPayloadFromMessage(PayloadType::SK);
        std::vector<uint8_t> decrypted_inner = sa->decryptPayload(payload_data);
        
        size_t inner_off = 0;
        PayloadHeader inner_hdr;
        
        // Parse IDr
        IdentityPayload idr = IdentityPayload::deserialize(decrypted_inner, inner_off);
        std::cout << "[Initiator] Got IDr payload" << std::endl;
        
        inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
        inner_off += inner_hdr.payload_length;
        
        // Parse AUTH
        if (inner_hdr.next_payload == PayloadType::AUTH) {
            AuthPayload auth = AuthPayload::deserialize(decrypted_inner, inner_off);
            std::cout << "[Initiator] Got AUTH payload" << std::endl;
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
        }
        
        // Parse SA
        if (inner_hdr.next_payload == PayloadType::SA) {
            SAPayload sa_payload = SAPayload::deserialize(decrypted_inner, inner_off);
            sa->getFirstChildSA()->setSpiOutbound(net_to_host32(*reinterpret_cast<const uint32_t*>(sa_payload.getProposals()[0].spi.data())));
            std::cout << "[Initiator] Got Child SA payload" << std::endl;
            sa_payload.debugPrint();
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
        }
        
        // Parse TSi
        if (inner_hdr.next_payload == PayloadType::TSi) {
            TrafficSelectorPayload tsi = TrafficSelectorPayload::deserialize(decrypted_inner, inner_off, true);
            std::cout << "[Initiator] Got TSi payload" << std::endl;
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
            std::vector<TrafficSelector> v1 = TrafficSelectorPayload::toListTrafficSelector(tsi);
            sa->getFirstChildSA()->setTrafficSelectorsI(v1);
        }
        
        // Parse TSr
        if (inner_hdr.next_payload == PayloadType::TSr) {
            TrafficSelectorPayload tsr = TrafficSelectorPayload::deserialize(decrypted_inner, inner_off, false);
            std::cout << "[Initiator] Got TSr payload" << std::endl;
            inner_hdr = PayloadHeader::deserialize(decrypted_inner, inner_off);
            inner_off += inner_hdr.payload_length;
            std::vector<TrafficSelector> v2 = TrafficSelectorPayload::toListTrafficSelector(tsr);
            sa->getFirstChildSA()->setTrafficSelectorsR(v2);
        }
        
        std::cout << "Finished parsing IKE_AUTH response." << std::endl;
        std::cout << sa->getFirstChildSA()->toString();
    }

public:
    // Status and debugging methods
    void printSAInfo() const {
        std::cout << "=== IKE SA Information ===\n";
        std::cout << "Role: " << (is_initiator ? "Initiator" : "Responder") << "\n";
        std::cout << "State: ";
        switch (current_state) {
            case ProtocolState::IDLE: std::cout << "IDLE"; break;
            case ProtocolState::SA_INIT_SENT: std::cout << "SA_INIT_SENT"; break;
            case ProtocolState::SA_INIT_RECEIVED: std::cout << "SA_INIT_RECEIVED"; break;
            case ProtocolState::AUTH_SENT: std::cout << "AUTH_SENT"; break;
            case ProtocolState::AUTH_RECEIVED: std::cout << "AUTH_RECEIVED"; break;
            case ProtocolState::ESTABLISHED: std::cout << "ESTABLISHED"; break;
            case ProtocolState::ERROR_STATE: std::cout << "ERROR"; break;
        }
        std::cout << "\n";
        
        std::cout << "Local Port: " << local_port << "\n";
        if (peer_addr.sin_addr.s_addr != 0) {
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peer_addr.sin_addr, addr_str, INET_ADDRSTRLEN);
            std::cout << "Peer Address: " << addr_str << ":" << ntohs(peer_addr.sin_port) << "\n";
        }
        
        std::cout << "Initiator SPI: 0x" << std::hex << sa->getInitiatorSPI() << std::dec << "\n";
        std::cout << "Responder SPI: 0x" << std::hex << sa->getResponderSPI() << std::dec << "\n";
        std::cout << "Preshared Key: " << preshared_key << "\n";
        
        if (!sa->getSK_ei().empty()) {
            std::cout << "\n=== Derived Keys ===\n";
            std::cout << "SK_d  (key derivation): " << sa->getSK_d().size() << " bytes\n";
            std::cout << "SK_ai (integrity-initiator): " << sa->getSK_ai().size() << " bytes\n";
            std::cout << "SK_ar (integrity-responder): " << sa->getSK_ar().size() << " bytes\n";
            std::cout << "SK_ei (encryption-initiator): " << sa->getSK_ei().size() << " bytes\n";
            std::cout << "SK_er (encryption-responder): " << sa->getSK_er().size() << " bytes\n";
            std::cout << "SK_pi (auth-initiator): " << sa->getSK_pi().size() << " bytes\n";
            std::cout << "SK_pr (auth-responder): " << sa->getSK_pr().size() << " bytes\n";
        } else {
            std::cout << "\nKeys not yet derived\n";
        }
        
        if (current_state == ProtocolState::ESTABLISHED && sa->getFirstChildSA()) {
            std::cout << "\n=== Child SA Information ===\n";
            std::cout << sa->getFirstChildSA()->toString();
        }
        
        std::cout << "==========================\n\n";
    }
    
    bool isEstablished() const {
        return current_state == ProtocolState::ESTABLISHED;
    }
    
    ProtocolState getState() const {
        return current_state;
    }
};

// Helper function to display usage
void printUsage(const char* program_name) {
    std::cout << "Usage:\n";
    std::cout << "  " << program_name << " initiator <peer_ip> [peer_port] [local_port] [psk]\n";
    std::cout << "  " << program_name << " responder [local_port] [psk]\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program_name << " responder 500 MySecretPSK123\n";
    std::cout << "  " << program_name << " initiator 192.168.1.100 500 501 MySecretPSK123\n";
    std::cout << "\nDefault values:\n";
    std::cout << "  peer_port: 500\n";
    std::cout << "  local_port: 500 (responder), 501 (initiator)\n";
    std::cout << "  psk: defaultpsk\n";
}

// Network testing and demonstration
int main(int argc, char* argv[]) {
    std::cout << "IKEv2 Network Protocol Implementation\n";
    std::cout << "====================================\n";
    
    // Parse command line arguments
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string mode = argv[1];
    
    try {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        if (mode == "responder") {
            // Responder mode
            uint16_t local_port = 500;
            std::string psk = "defaultpsk";
            
            if (argc > 2) local_port = std::stoi(argv[2]);
            if (argc > 3) psk = argv[3];
            
            std::cout << "Starting as RESPONDER on port " << local_port 
                      << " with PSK: " << psk << "\n\n";
            
            IKEv2NetworkProtocol responder(false, psk, local_port);
            responder.printSAInfo();
            
            // Listen for connections
            if (responder.listenAndRespond()) {
                std::cout << "\n=== Final Status ===\n";
                responder.printSAInfo();
                
                // Keep running to maintain the connection
                std::cout << "Connection established. Press Ctrl+C to exit.\n";
                while (responder.isEstablished()) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            } else {
                std::cerr << "Failed to establish connection" << std::endl;
                return 1;
            }
            
        } else if (mode == "initiator") {
            // Initiator mode
            if (argc < 3) {
                std::cerr << "Error: Initiator mode requires peer IP address" << std::endl;
                printUsage(argv[0]);
                return 1;
            }
            
            std::string peer_ip = argv[2];
            uint16_t peer_port = 500;
            uint16_t local_port = 501;
            std::string psk = "defaultpsk";
            
            if (argc > 3) peer_port = std::stoi(argv[3]);
            if (argc > 4) local_port = std::stoi(argv[4]);
            if (argc > 5) psk = argv[5];
            
            std::cout << "Starting as INITIATOR on port " << local_port 
                      << " connecting to " << peer_ip << ":" << peer_port
                      << " with PSK: " << psk << "\n\n";
            
            IKEv2NetworkProtocol initiator(true, psk, local_port);
            initiator.printSAInfo();
            
            // Initiate connection
            if (initiator.initiateIKEExchange(peer_ip, peer_port)) {
                std::cout << "\n=== Final Status ===\n";
                initiator.printSAInfo();
                
                // Keep running to maintain the connection
                std::cout << "Connection established. Press Ctrl+C to exit.\n";
                while (initiator.isEstablished()) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            } else {
                std::cerr << "Failed to establish connection" << std::endl;
                return 1;
            }
            
        } else {
            std::cerr << "Error: Unknown mode '" << mode << "'" << std::endl;
            printUsage(argv[0]);
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
        
    return 0;
}