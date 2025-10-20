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
#include <mutex>

// Network headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <fstream>

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
//g++ -std=c++14 -O2 -Wall -Wextra -o main2 main2.cpp -lssl -lcrypto -lpthread
// sudo ./main2 responder 8080 MySecretPSK123
// sudo ./main2 initiator 192.168.1.6 8080 8081 MySecretPSK123
// scp /home/chien/vpn/main2 chien@192.168.1.19:/home/chien/
// scp /home/chien/vpn/main2 chien@172.31.213.48:/home/chien/
// sudo ./main2 initiator 172.31.213.79 8080 8081 MySecretPSK123
// 172.31.213.79
// sudo tcpdump -n icmp
// busybox httpd -f -p 8080 -h ~/web

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
        SAPayload child_sa = SAPayload::createChildSAProposal(sa->getFirstChildSA()->getOutboundSPI());
        std::vector<uint8_t> child_sa_serial = child_sa.serialize(PayloadType::TSi);
        inner_plain.insert(inner_plain.end(), child_sa_serial.begin(), child_sa_serial.end());
        
        // TSi
        TrafficSelectorPayload tsi(true);
        TrafficSelector ts_init;
        ts_init.ts_type = 7;
        ts_init.ip_protocol_id = 0;
        ts_init.selector_length = 16;
        ts_init.start_port = 0;
        ts_init.end_port = 65535;
        ts_init.starting_address = {10,0,0,2};
        ts_init.ending_address  = {10,0,0,2};
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
        ts_resp.starting_address = {192,168,50,0};
        ts_resp.ending_address  = {192,168,50,255};
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
        SAPayload chosen_sa = SAPayload::createChildSAProposal(sa->getFirstChildSA()->getOutboundSPI());
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
        ts_init.starting_address = {10,0,0,2};
        ts_init.ending_address  = {10,0,0,2};
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
        ts_resp.starting_address = {192,168,50,0};
        ts_resp.ending_address  = {192,168,50,255};
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
            sa->getFirstChildSA()->setSpiInbound(net_to_host32(*reinterpret_cast<const uint32_t*>(sa_payload.getProposals()[0].spi.data())));
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
            sa->getFirstChildSA()->setSpiInbound(net_to_host32(*reinterpret_cast<const uint32_t*>(sa_payload.getProposals()[0].spi.data())));
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



#define ESP_PROTOCOL 50
#define UDP_ESP_PORT 4500
#define MAX_PACKET_SIZE 10000
#define ESP_HEADER_SIZE 8
#define ESP_TRAILER_MIN_SIZE 2
#define ESP_AUTH_SIZE 16
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define HMAC_KEY_SIZE 32

struct PacketInfo {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};


// ============================================================================
// TRAFFIC SELECTOR - Định nghĩa traffic nào được bảo vệ
// ============================================================================
struct TrafficSelector2 {
    uint32_t src_addr;      // Network byte order
    uint32_t src_mask;
    uint32_t dst_addr;
    uint32_t dst_mask;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    uint8_t protocol;       // 0 = any, IPPROTO_TCP, IPPROTO_UDP, etc.
    
    TrafficSelector2() :
        src_addr(0), src_mask(0),
        dst_addr(0), dst_mask(0),
        src_port_start(0), src_port_end(65535),
        dst_port_start(0), dst_port_end(65535),
        protocol(0) {}
    
    // Parse CIDR notation
    static TrafficSelector2 fromCIDR(const std::string& src_cidr, 
                                    const std::string& dst_cidr,
                                    uint8_t proto = 0) {
        TrafficSelector2 ts;
        ts.protocol = proto;
        
        // Parse source
        auto parse_cidr = [](const std::string& cidr, uint32_t& addr, uint32_t& mask) {
            size_t slash = cidr.find('/');
            std::string ip_str = cidr.substr(0, slash);
            int prefix_len = (slash != std::string::npos) ? 
                            std::stoi(cidr.substr(slash + 1)) : 32;
            
            addr = inet_addr(ip_str.c_str());
            mask = htonl(~((1ULL << (32 - prefix_len)) - 1));
        };
        
        parse_cidr(src_cidr, ts.src_addr, ts.src_mask);
        parse_cidr(dst_cidr, ts.dst_addr, ts.dst_mask);
        
        return ts;
    }
    
    // Check if packet matches this selector
    bool matches(uint32_t src_ip, uint32_t dst_ip, 
                uint16_t src_port, uint16_t dst_port, 
                uint8_t proto) const {
        // Check source address
        if ((src_ip & src_mask) != (src_addr & src_mask)) {
            return false;
        }
        
        // Check destination address
        if ((dst_ip & dst_mask) != (dst_addr & dst_mask)) {
            return false;
        }
        
        // Check protocol
        if (protocol != 0 && protocol != proto) {
            return false;
        }
        
        // Check ports
        if (src_port < src_port_start || src_port > src_port_end) {
            return false;
        }
        if (dst_port < dst_port_start || dst_port > dst_port_end) {
            return false;
        }
        
        return true;
    }
    
    std::string toString() const {
        char buf[256];
        struct in_addr addr;
        
        addr.s_addr = src_addr;
        std::string src_str = inet_ntoa(addr);
        addr.s_addr = dst_addr;
        std::string dst_str = inet_ntoa(addr);
        
        snprintf(buf, sizeof(buf), "%s -> %s proto:%d ports:[%d-%d]->[%d-%d]",
                src_str.c_str(), dst_str.c_str(), protocol,
                src_port_start, src_port_end, dst_port_start, dst_port_end);
        return std::string(buf);
    }
};

// ============================================================================
// SPD ENTRY - Security Policy Database Entry
// ============================================================================
enum SPDAction {
    SPD_DISCARD,    // Drop packet
    SPD_BYPASS,     // Send in clear (no IPsec)
    SPD_PROTECT     // Apply IPsec
};

struct SPDEntry {
    uint32_t id;                    // Unique ID
    TrafficSelector2 selector;       // Traffic selector
    SPDAction action;               // What to do
    uint32_t sa_bundle_id;          // ID của SA bundle (nếu PROTECT)
    int priority;                   // Priority (higher = more specific)
    
    // Statistics
    uint64_t packets_matched;
    uint64_t bytes_matched;
    
    SPDEntry() : 
        id(0), action(SPD_BYPASS), sa_bundle_id(0), 
        priority(0), packets_matched(0), bytes_matched(0) {}
    
    std::string actionToString() const {
        switch(action) {
            case SPD_DISCARD: return "DISCARD";
            case SPD_BYPASS: return "BYPASS";
            case SPD_PROTECT: return "PROTECT";
            default: return "UNKNOWN";
        }
    }
    
    void updateStats(size_t bytes) {
        packets_matched++;
        bytes_matched += bytes;
    }
};

// ============================================================================
// SAD ENTRY - Security Association Database Entry  
// ============================================================================
enum SAMode {
    SA_MODE_TRANSPORT,
    SA_MODE_TUNNEL
};

enum SAState {
    SA_STATE_LARVAL,    // Being negotiated
    SA_STATE_MATURE,    // Active and usable
    SA_STATE_DYING,     // Soft lifetime exceeded
    SA_STATE_DEAD       // Hard lifetime exceeded
};

struct SADEntry {
    // SA Identity
    uint32_t spi;                   // Security Parameter Index
    uint32_t dst_addr;              // Destination IP (network byte order)
    uint8_t protocol;               // ESP = 50

    uint16_t udp_encap_src_port;
    uint16_t udp_encap_dst_port;
    
    // SA Parameters
    SAMode mode;
    SAState state;
    TrafficSelector2 selector;       // Traffic covered by this SA
    
    // Tunnel mode endpoints (if mode == TUNNEL)
    uint32_t tunnel_src;
    uint32_t tunnel_dst;
    
    // Cryptographic material
    uint8_t encryption_key[AES_KEY_SIZE];
    uint8_t authentication_key[HMAC_KEY_SIZE];
    
    // Sequence number (anti-replay)
    uint32_t sequence_number;       // For outbound
    uint32_t replay_window_last;    // For inbound
    uint64_t replay_bitmap;         // 64-bit sliding window
    
    // Lifetimes (RFC 4301 Section 4.5)
    struct {
        uint64_t bytes_soft;
        uint64_t bytes_hard;
        uint64_t packets_soft;
        uint64_t packets_hard;
        std::chrono::seconds time_soft;
        std::chrono::seconds time_hard;
    } lifetime;
    
    // Statistics
    uint64_t packets_processed;
    uint64_t bytes_processed;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_used;
    
    // Path MTU
    uint16_t path_mtu;
    
    SADEntry() : 
        spi(0), dst_addr(0), protocol(ESP_PROTOCOL),
        mode(SA_MODE_TUNNEL),udp_encap_src_port(0),udp_encap_dst_port(0), state(SA_STATE_MATURE),
        tunnel_src(0), tunnel_dst(0),
        sequence_number(0), replay_window_last(0), replay_bitmap(0),
        packets_processed(0), bytes_processed(0),
        path_mtu(1500) {
        
        created_at = std::chrono::system_clock::now();
        last_used = created_at;
        
        // Default lifetimes
        lifetime.bytes_soft = 100 * 1024 * 1024;      // 100 MB
        lifetime.bytes_hard = 150 * 1024 * 1024;      // 150 MB
        lifetime.packets_soft = 1000000;
        lifetime.packets_hard = 1500000;
        lifetime.time_soft = std::chrono::hours(8);
        lifetime.time_hard = std::chrono::hours(12);
    }
    
    // Anti-replay check (RFC 4303 Section 3.4.3)
    bool checkReplayWindow(uint32_t seq) {
        if (seq == 0) {
            std::cout << "[Anti-Replay] REJECT: seq=0 invalid" << std::endl;
            return false;
        }
        
        if (replay_window_last == 0) {
            std::cout << "[Anti-Replay] ACCEPT: First packet" << std::endl;
            replay_window_last = seq;
            replay_bitmap = 1;
            return true;
        }
        
        if (seq + 64 < replay_window_last) {
            std::cout << "[Anti-Replay] REJECT: Too old" << std::endl;
            return false;
        }
        
        if (seq > replay_window_last) {
            std::cout << "[Anti-Replay] ACCEPT: Advancing window" << std::endl;
            uint32_t diff = seq - replay_window_last;
            if (diff < 64) {
                replay_bitmap = (replay_bitmap << diff) | 1;
            } else {
                replay_bitmap = 1;
            }
            replay_window_last = seq;
            return true;
        }
        
        uint32_t diff = replay_window_last - seq;
        uint64_t mask = 1ULL << diff;
        
        std::cout << "[Anti-Replay] Checking window: diff=" << diff 
                << " mask=0x" << std::hex << mask << std::dec << std::endl;
        
        if (replay_bitmap & mask) {
            std::cout << "[Anti-Replay] REJECT: Duplicate" << std::endl;
            return false;
        }
        
        std::cout << "[Anti-Replay] ACCEPT: Within window" << std::endl;
        replay_bitmap |= mask;
        return true;
    }
    
    // Check if SA needs rekey (soft lifetime exceeded)
    bool needsRekey() const {
        if (state != SA_STATE_MATURE) return false;
        
        // Check bytes
        if (bytes_processed >= lifetime.bytes_soft) return true;
        
        // Check packets
        if (packets_processed >= lifetime.packets_soft) return true;
        
        // Check time
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - created_at);
        if (age >= lifetime.time_soft) return true;
        
        return false;
    }
    
    // Check if SA is expired (hard lifetime exceeded)
    bool isExpired() const {
        // Check bytes
        if (bytes_processed >= lifetime.bytes_hard) return true;
        
        // Check packets  
        if (packets_processed >= lifetime.packets_hard) return true;
        
        // Check time
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - created_at);
        if (age >= lifetime.time_hard) return true;
        
        return false;
    }
    
    void updateStats(size_t bytes) {
        packets_processed++;
        bytes_processed += bytes;
        last_used = std::chrono::system_clock::now();
        
        // Update state based on lifetime
        if (isExpired()) {
            state = SA_STATE_DEAD;
        } else if (needsRekey() && state == SA_STATE_MATURE) {
            state = SA_STATE_DYING;
        }
    }
    
    std::string toString() const {
        char buf[512];
        struct in_addr addr;
        
        addr.s_addr = dst_addr;
        std::string dst_str = inet_ntoa(addr);
        
        const char* mode_str = (mode == SA_MODE_TUNNEL) ? "TUNNEL" : "TRANSPORT";
        const char* state_str;
        switch(state) {
            case SA_STATE_LARVAL: state_str = "LARVAL"; break;
            case SA_STATE_MATURE: state_str = "MATURE"; break;
            case SA_STATE_DYING: state_str = "DYING"; break;
            case SA_STATE_DEAD: state_str = "DEAD"; break;
            default: state_str = "UNKNOWN";
        }
        
        snprintf(buf, sizeof(buf), 
                "SPI:0x%08x dst:%s mode:%s state:%s seq:%u pkts:%lu bytes:%lu",
                spi, dst_str.c_str(), mode_str, state_str,
                sequence_number, packets_processed, bytes_processed);
        
        return std::string(buf);
    }
};

// ============================================================================
// PAD ENTRY - Peer Authorization Database Entry
// ============================================================================
enum AuthMethod {
    AUTH_PSK,           // Pre-shared key
    AUTH_RSA_SIG,       // RSA signature
    AUTH_ECDSA_SIG,     // ECDSA signature
    AUTH_NULL           // No authentication (testing only!)
};

struct PADEntry {
    uint32_t id;
    std::string peer_identity;      // ID (IP, FQDN, email, etc.)
    AuthMethod auth_method;
    std::vector<uint8_t> auth_data; // PSK, certificate, public key, etc.
    
    // Child SA parameters that are acceptable
    std::vector<std::string> allowed_ciphers;
    std::vector<std::string> allowed_auth_algos;
    
    // Authorization: what traffic is allowed
    std::vector<TrafficSelector2> allowed_selectors;
    
    PADEntry() : id(0), auth_method(AUTH_NULL) {}
    
    // Check if peer is authorized for this traffic
    bool authorizeTraffic(const TrafficSelector2& ts) const {
        if (allowed_selectors.empty()) {
            return true;  // No restrictions
        }
        
        // Check if requested TS is subset of allowed
        for (const auto& allowed : allowed_selectors) {
            // Simplified check - in production, do proper subset comparison
            if ((ts.src_addr & allowed.src_mask) == (allowed.src_addr & allowed.src_mask) &&
                (ts.dst_addr & allowed.dst_mask) == (allowed.dst_addr & allowed.dst_mask)) {
                return true;
            }
        }
        
        return false;
    }
    
    std::string toString() const {
        std::string auth_str;
        switch(auth_method) {
            case AUTH_PSK: auth_str = "PSK"; break;
            case AUTH_RSA_SIG: auth_str = "RSA-SIG"; break;
            case AUTH_ECDSA_SIG: auth_str = "ECDSA-SIG"; break;
            case AUTH_NULL: auth_str = "NULL"; break;
            default: auth_str = "UNKNOWN";
        }
        
        return "ID:" + peer_identity + " Auth:" + auth_str;
    }
};

// ============================================================================
// SPD - Security Policy Database
// ============================================================================
class SPD {
private:
    std::map<uint32_t, SPDEntry> entries;
    std::mutex mutex;
    uint32_t next_id;
    
public:
    SPD() : next_id(1) {}
    
    uint32_t addEntry(const TrafficSelector2& ts, SPDAction action, 
                     uint32_t sa_bundle_id = 0, int priority = 100) {
        std::lock_guard<std::mutex> lock(mutex);
        
        SPDEntry entry;
        entry.id = next_id++;
        entry.selector = ts;
        entry.action = action;
        entry.sa_bundle_id = sa_bundle_id;
        entry.priority = priority;
        
        entries[entry.id] = entry;
        
        std::cout << "[SPD] Added entry " << entry.id 
                  << ": " << entry.actionToString()
                  << " for " << ts.toString() << std::endl;
        
        return entry.id;
    }
    
    void removeEntry(uint32_t id) {
        std::lock_guard<std::mutex> lock(mutex);
        entries.erase(id);
        std::cout << "[SPD] Removed entry " << id << std::endl;
    }
    
    // Lookup policy for outbound packet
    SPDEntry* lookupOutbound(uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint8_t protocol) {
        std::lock_guard<std::mutex> lock(mutex);
        
        SPDEntry* best_match = nullptr;
        int best_priority = -1;
        
        for (auto& pair : entries) {
            SPDEntry& entry = pair.second;
            
            if (entry.selector.matches(src_ip, dst_ip, src_port, dst_port, protocol)) {
                if (entry.priority > best_priority) {
                    best_match = &entry;
                    best_priority = entry.priority;
                }
            }
        }
        
        return best_match;
    }
    
    // Lookup policy for inbound packet (after IPsec processing)
    SPDEntry* lookupInbound(uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint8_t protocol, uint32_t spi) {
        std::lock_guard<std::mutex> lock(mutex);
        
        // Find policy that matches and has correct SA
        for (auto& pair : entries) {
            SPDEntry& entry = pair.second;
            
            if (entry.action == SPD_PROTECT &&
                entry.selector.matches(src_ip, dst_ip, src_port, dst_port, protocol)) {
                // In production: check if SPI belongs to entry.sa_bundle_id
                return &entry;
            }
        }
        
        return nullptr;
    }
    
    void printAll() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
        
        std::cout << "\n=== Security Policy Database (SPD) ===" << std::endl;
        std::cout << "Total entries: " << entries.size() << std::endl;
        
        for (const auto& pair : entries) {
            const SPDEntry& entry = pair.second;
            std::cout << "\nEntry ID: " << entry.id 
                      << " (Priority: " << entry.priority << ")" << std::endl;
            std::cout << "  Action: " << entry.actionToString() << std::endl;
            std::cout << "  Selector: " << entry.selector.toString() << std::endl;
            if (entry.action == SPD_PROTECT) {
                std::cout << "  SA Bundle: " << entry.sa_bundle_id << std::endl;
            }
            std::cout << "  Stats: " << entry.packets_matched << " packets, "
                      << entry.bytes_matched << " bytes" << std::endl;
        }
        std::cout << "======================================\n" << std::endl;
    }
};

// ============================================================================
// SAD - Security Association Database
// ============================================================================
class SAD {
private:
    // Key: SPI
    std::map<uint32_t, SADEntry> entries;
    std::mutex mutex;
    
public:
    SAD() {}
    
    uint32_t addEntry(const SADEntry& sa) {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (entries.find(sa.spi) != entries.end()) {
            std::cerr << "[SAD] SPI 0x" << std::hex << sa.spi << std::dec 
                      << " already exists!" << std::endl;
            return 0;
        }
        
        entries[sa.spi] = sa;
        
        std::cout << "[SAD] Added SA: " << sa.toString() << std::endl;
        
        return sa.spi;
    }
    
    void removeEntry(uint32_t spi) {
        std::lock_guard<std::mutex> lock(mutex);
        entries.erase(spi);
        std::cout << "[SAD] Removed SA with SPI 0x" << std::hex << spi << std::dec << std::endl;
    }
    
    SADEntry* lookup(uint32_t spi) {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = entries.find(spi);
        return (it != entries.end()) ? &it->second : nullptr;
    }
    
    // Find outbound SA for given traffic
    SADEntry* lookupOutbound(uint32_t dst_ip, const TrafficSelector2& ts) {
        std::lock_guard<std::mutex> lock(mutex);
        
        for (auto& pair : entries) {
            SADEntry& sa = pair.second;
            
            // Check destination, state
            if (sa.dst_addr != dst_ip || sa.state != SA_STATE_MATURE) {
                continue;
            }
            std::cout<<"+++++++++++++++++++++++++++++++++++++++++++++++++"<<std::endl;
            ts.toString();
            sa.selector.toString();
            std::cout<<"+++++++++++++++++++++++++++++++++++++++++++++++++"<<std::endl;
            
            // ✅ Check if traffic matches SA's selector
            // SA selector defines what traffic this SA protects
            if ((ts.src_addr & sa.selector.src_mask) == (sa.selector.src_addr & sa.selector.src_mask) &&
                (ts.dst_addr & sa.selector.dst_mask) == (sa.selector.dst_addr & sa.selector.dst_mask) &&
                (sa.selector.protocol == 0 || sa.selector.protocol == ts.protocol)) {
                return &sa;
            }
        }
        
        return nullptr;
    }
    
    void cleanupExpired() {
        std::lock_guard<std::mutex> lock(mutex);
        
        std::vector<uint32_t> to_remove;
        for (auto& pair : entries) {
            if (pair.second.state == SA_STATE_DEAD) {
                to_remove.push_back(pair.first);
            }
        }
        
        for (uint32_t spi : to_remove) {
            std::cout << "[SAD] Removing expired SA 0x" << std::hex << spi << std::dec << std::endl;
            entries.erase(spi);
        }
    }
    
    void printAll() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
        
        std::cout << "\n=== Security Association Database (SAD) ===" << std::endl;
        std::cout << "Total entries: " << entries.size() << std::endl;
        
        for (const auto& pair : entries) {
            const SADEntry& sa = pair.second;
            std::cout << "\n" << sa.toString() << std::endl;
            std::cout << "  Selector: " << sa.selector.toString() << std::endl;
            
            if (sa.mode == SA_MODE_TUNNEL) {
                struct in_addr addr;
                addr.s_addr = sa.tunnel_src;
                std::string src_str = inet_ntoa(addr);
                addr.s_addr = sa.tunnel_dst;
                std::string dst_str = inet_ntoa(addr);
                std::cout << "  Tunnel: " << src_str << " -> " << dst_str << std::endl;
            }
            
            // Lifetime status
            std::cout << "  Lifetime: ";
            if (sa.isExpired()) {
                std::cout << "EXPIRED";
            } else if (sa.needsRekey()) {
                std::cout << "NEEDS_REKEY";
            } else {
                std::cout << "OK";
            }
            std::cout << std::endl;
        }
        std::cout << "==========================================\n" << std::endl;
    }
};

// ============================================================================
// PAD - Peer Authorization Database
// ============================================================================
class PAD {
private:
    std::map<uint32_t, PADEntry> entries;
    std::mutex mutex;
    uint32_t next_id;
    
public:
    PAD() : next_id(1) {}
    
    uint32_t addEntry(const PADEntry& entry) {
        std::lock_guard<std::mutex> lock(mutex);
        
        PADEntry new_entry = entry;
        new_entry.id = next_id++;
        entries[new_entry.id] = new_entry;
        
        std::cout << "[PAD] Added peer: " << new_entry.toString() << std::endl;
        
        return new_entry.id;
    }
    
    void removeEntry(uint32_t id) {
        std::lock_guard<std::mutex> lock(mutex);
        entries.erase(id);
    }
    
    PADEntry* lookupByIdentity(const std::string& identity) {
        std::lock_guard<std::mutex> lock(mutex);
        
        for (auto& pair : entries) {
            if (pair.second.peer_identity == identity) {
                return &pair.second;
            }
        }
        
        return nullptr;
    }
    
    // Authenticate peer and check authorization
    bool authenticateAndAuthorize(const std::string& peer_id,
                                  const std::vector<uint8_t>& auth_data,
                                  const TrafficSelector2& requested_ts) {
        PADEntry* entry = lookupByIdentity(peer_id);
        if (!entry) {
            std::cout << "[PAD] Peer not found: " << peer_id << std::endl;
            return false;
        }
        
        // Authenticate (simplified - in production do real crypto)
        if (entry->auth_method == AUTH_PSK) {
            if (entry->auth_data != auth_data) {
                std::cout << "[PAD] Authentication failed for " << peer_id << std::endl;
                return false;
            }
        }
        
        // Authorize traffic
        if (!entry->authorizeTraffic(requested_ts)) {
            std::cout << "[PAD] Authorization failed for " << peer_id 
                      << " traffic: " << requested_ts.toString() << std::endl;
            return false;
        }
        
        std::cout << "[PAD] Authenticated and authorized: " << peer_id << std::endl;
        return true;
    }
    
    void printAll() const {
        std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex));
        
        std::cout << "\n=== Peer Authorization Database (PAD) ===" << std::endl;
        std::cout << "Total entries: " << entries.size() << std::endl;
        
        for (const auto& pair : entries) {
            const PADEntry& entry = pair.second;
            std::cout << "\nPeer ID " << entry.id << ": " 
                      << entry.toString() << std::endl;
            std::cout << "  Allowed selectors: " << entry.allowed_selectors.size() << std::endl;
        }
        std::cout << "==========================================\n" << std::endl;
    }
};

// Compile: g++ -std=c++17 -o esp_vpn_integrated esp_vpn_integrated.cpp -lssl -lcrypto -lpthread
// Run: sudo ./esp_vpn_integrated

struct ESPHeader {
    uint32_t spi;
    uint32_t sequence;
} __attribute__((packed));

struct ESPTrailer {
    uint8_t padding_length;
    uint8_t next_header;
} __attribute__((packed));

struct IPHeader {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed));

PacketInfo extractPacketInfo(const uint8_t* buffer, size_t size) {
    PacketInfo info = {0};
    
    if (size < sizeof(IPHeader)) return info;
    
    const IPHeader* ip_hdr = reinterpret_cast<const IPHeader*>(buffer);
    info.src_ip = ip_hdr->src_addr;
    info.dst_ip = ip_hdr->dst_addr;
    info.protocol = ip_hdr->protocol;
    
    // Extract ports nếu là TCP/UDP
    size_t ip_header_len = (ip_hdr->version_ihl & 0x0F) * 4;
    
    if ((info.protocol == IPPROTO_TCP || info.protocol == IPPROTO_UDP) &&
        size >= ip_header_len + 4) {
        const uint16_t* ports = reinterpret_cast<const uint16_t*>(buffer + ip_header_len);
        info.src_port = ntohs(ports[0]);
        info.dst_port = ntohs(ports[1]);
    }
    
    return info;
}


class ESPVPNTunnel {
protected:
    // RFC 4301 compliant databases
    SPD spd;
    SAD sad;
    PAD pad;
    
    std::mutex database_mutex;
    
    int raw_socket;
    int udp_socket;
    int tun_fd;
    bool is_server;
    std::string tunnel_ip;
    std::string lan_network;
    
    std::thread receive_thread;
    std::thread tun_thread;
    bool running;
    
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t packets_encrypted;
    uint64_t packets_decrypted;
    uint64_t packets_dropped;

public:
    ESPVPNTunnel(bool server_mode = false) : 
        is_server(server_mode), 
        running(false),
        packets_sent(0),
        packets_received(0),
        packets_encrypted(0),
        packets_decrypted(0),
        packets_dropped(0),
        tun_fd(-1),
        raw_socket(-1),
        udp_socket(-1) {
        
        if(is_server){
            tunnel_ip = "10.0.0.1";
            lan_network = "192.168.50.0/24";
        } else {
            tunnel_ip = "10.0.0.2";
        }
    }

    ~ESPVPNTunnel() {
        stop();
        if (raw_socket >= 0) close(raw_socket);
        if (udp_socket >= 0) close(udp_socket);
        if (tun_fd >= 0) close(tun_fd);
    }

    std::string getMainInterface() {
        std::ifstream route_file("/proc/net/route");
        std::string line, interface, destination;
        
        if (!route_file.is_open()) {
            return "ens33";
        }
        
        std::getline(route_file, line);
        
        while (std::getline(route_file, line)) {
            std::istringstream iss(line);
            if (iss >> interface >> destination) {
                if (destination == "00000000") {
                    return interface;
                }
            }
        }
        
        return "ens33";
    }

    bool createTunInterface(const std::string& tun_name = "tun1") {
        struct ifreq ifr;
        
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            std::cerr << "Cannot open /dev/net/tun" << std::endl;
            return false;
        }
        
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, tun_name.c_str(), IFNAMSIZ);
        
        if (ioctl(tun_fd, TUNSETIFF, (void*)&ifr) < 0) {
            std::cerr << "Cannot create TUN interface" << std::endl;
            close(tun_fd);
            tun_fd = -1;
            return false;
        }
        
        std::cout << "TUN interface " << ifr.ifr_name << " created successfully" << std::endl;
        
        std::string cmd;
        if (is_server) {
            cmd = "ip addr add " + tunnel_ip + "/24 dev " + tun_name;
            system(cmd.c_str());
            
            cmd = "ip link set " + tun_name + " up";
            system(cmd.c_str());
            
            system("echo 1 > /proc/sys/net/ipv4/ip_forward");
            
            std::string main_interface = getMainInterface();
            std::string lan_interface = "ens37";
            
            cmd = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 192.168.50.0/24 -o " + lan_interface + " -j MASQUERADE";
            system(cmd.c_str());
            
            cmd = "iptables -A FORWARD -s 10.0.0.0/24 -d 192.168.50.0/24 -j ACCEPT";
            system(cmd.c_str());
            
            cmd = "iptables -A FORWARD -s 192.168.50.0/24 -d 10.0.0.0/24 -j ACCEPT";
            system(cmd.c_str());
            
        } else {
            cmd = "ip addr add " + tunnel_ip + "/24 dev " + tun_name;
            system(cmd.c_str());
            
            cmd = "ip link set " + tun_name + " up";
            system(cmd.c_str());
            
            cmd = "ip route add 192.168.50.0/24 via 10.0.0.1 dev " + tun_name;
            system(cmd.c_str());
        }
        
        return true;
    }

    bool initialize(const std::string& local_addr, uint16_t local_p) {
        if (!createTunInterface()) {
            std::cerr << "Failed to create TUN interface" << std::endl;
            return false;
        }
        
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket < 0) {
            std::cerr << "Failed to create UDP socket" << std::endl;
            return false;
        }
        
        struct sockaddr_in local_addr_struct;
        memset(&local_addr_struct, 0, sizeof(local_addr_struct));
        local_addr_struct.sin_family = AF_INET;
        local_addr_struct.sin_addr.s_addr = inet_addr(local_addr.c_str());
        local_addr_struct.sin_port = htons(local_p);
        
        if (bind(udp_socket, (struct sockaddr*)&local_addr_struct, sizeof(local_addr_struct)) < 0) {
            std::cerr << "Failed to bind UDP socket to " << local_addr << ":" << local_p << std::endl;
            return false;
        }
        
        std::cout << "ESP VPN Tunnel initialized on " << local_addr << ":" << local_p << std::endl;
        return true;
    }
    bool setupSecurityPolicy(const std::string& local_addr, uint16_t local_p,
                            const std::string& remote_addr, uint16_t remote_p,
                            bool is_initiator, ChildSA chil_sa) {
        std::lock_guard<std::mutex> lock(database_mutex);
        
        std::cout << "[Security] Setting up as " << (is_initiator ? "INITIATOR" : "RESPONDER") << std::endl;
        
        // ========================================================================
        // 1. Setup PAD entry for peer
        // ========================================================================
        PADEntry peer;
        peer.peer_identity = remote_addr;
        peer.auth_method = AUTH_PSK;
        
        // Shared PSK (same on both sides)
        std::vector<uint8_t> psk(32, 0xAA);
        peer.auth_data = psk;
        
        // Allow all traffic from this peer
        TrafficSelector2 allowed_ts = TrafficSelector2::fromCIDR("0.0.0.0/0", "0.0.0.0/0");
        peer.allowed_selectors.push_back(allowed_ts);
        
        uint32_t pad_id = pad.addEntry(peer);
        std::cout << "[PAD] Added peer " << remote_addr << " with ID " << pad_id << std::endl;
        
        // ========================================================================
        // 2. SPIs - CRITICAL: Must be opposite on each side!
        // ========================================================================
        uint32_t my_outbound_spi;
        uint32_t my_inbound_spi;
        
        if (is_initiator) {
            // Initiator uses these SPIs
            my_outbound_spi = 0x11111111;  // I send with this SPI
            my_inbound_spi  = 0x22222222;  // I receive with this SPI
            
            std::cout << "[Initiator] My outbound SPI: 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
            std::cout << "[Initiator] My inbound SPI:  0x" << std::hex << my_inbound_spi << std::dec << std::endl;
        } else {
            // Responder uses OPPOSITE SPIs
            my_outbound_spi = 0x22222222;  // I send with this SPI (= initiator's inbound)
            my_inbound_spi  = 0x11111111;  // I receive with this SPI (= initiator's outbound)
            
            std::cout << "[Responder] My outbound SPI: 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
            std::cout << "[Responder] My inbound SPI:  0x" << std::hex << my_inbound_spi << std::dec << std::endl;
        }
        
        // ========================================================================
        // 3. Keys - In production, these come from IKEv2 key derivation
        // ========================================================================
        
        // Base key material (would be DH shared secret in real IKEv2)
        uint8_t key_material[64];
        memset(key_material, 0xCD, 64);
        
        // Derive different keys for initiator and responder
        // Using simple derivation: initiator uses first half, responder uses second half
        uint8_t initiator_enc_key[AES_KEY_SIZE];
        uint8_t initiator_auth_key[HMAC_KEY_SIZE];
        uint8_t responder_enc_key[AES_KEY_SIZE];
        uint8_t responder_auth_key[HMAC_KEY_SIZE];
        
        if (is_initiator) {
            // Initiator's keys
            static const uint8_t init_enc[AES_KEY_SIZE] = {
                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
                0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
                0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
            };
            static const uint8_t init_auth[HMAC_KEY_SIZE] = {
                0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
                0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
                0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
                0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
            };
            memcpy(initiator_enc_key, init_enc, AES_KEY_SIZE);
            memcpy(initiator_auth_key, init_auth, HMAC_KEY_SIZE);
            
            // Responder's keys (for decrypting incoming packets)
            static const uint8_t resp_enc[AES_KEY_SIZE] = {
                0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
                0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
                0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F
            };
            static const uint8_t resp_auth[HMAC_KEY_SIZE] = {
                0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,
                0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
                0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,
                0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF
            };
            memcpy(responder_enc_key, resp_enc, AES_KEY_SIZE);
            memcpy(responder_auth_key, resp_auth, HMAC_KEY_SIZE);
        } else {
            // Responder: Use OPPOSITE keys
            static const uint8_t resp_enc[AES_KEY_SIZE] = {
                0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
                0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,
                0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
                0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F
            };
            static const uint8_t resp_auth[HMAC_KEY_SIZE] = {
                0xC0,0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,
                0xC8,0xC9,0xCA,0xCB,0xCC,0xCD,0xCE,0xCF,
                0xD0,0xD1,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,
                0xD8,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF
            };
            memcpy(responder_enc_key, resp_enc, AES_KEY_SIZE);
            memcpy(responder_auth_key, resp_auth, HMAC_KEY_SIZE);
            
            static const uint8_t init_enc[AES_KEY_SIZE] = {
                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
                0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
                0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
            };
            static const uint8_t init_auth[HMAC_KEY_SIZE] = {
                0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
                0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
                0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
                0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
            };
            memcpy(initiator_enc_key, init_enc, AES_KEY_SIZE);
            memcpy(initiator_auth_key, init_auth, HMAC_KEY_SIZE);
        }
        
        // ========================================================================
        // 4. Create Outbound SA (for packets I send)
        // ========================================================================
        SADEntry outbound_sa;
        outbound_sa.spi = my_outbound_spi;
        outbound_sa.dst_addr = inet_addr(remote_addr.c_str());
        outbound_sa.protocol = ESP_PROTOCOL;
        outbound_sa.udp_encap_src_port = local_p;
        outbound_sa.udp_encap_dst_port = remote_p;
        outbound_sa.mode = SA_MODE_TUNNEL;
        outbound_sa.state = SA_STATE_MATURE;
        outbound_sa.tunnel_src = inet_addr(local_addr.c_str());
        outbound_sa.tunnel_dst = inet_addr(remote_addr.c_str());
        
        // My outbound SA uses MY keys (initiator or responder keys based on role)
        if (is_initiator) {
            memcpy(outbound_sa.encryption_key, initiator_enc_key, AES_KEY_SIZE);
            memcpy(outbound_sa.authentication_key, initiator_auth_key, HMAC_KEY_SIZE);
        } else {
            memcpy(outbound_sa.encryption_key, responder_enc_key, AES_KEY_SIZE);
            memcpy(outbound_sa.authentication_key, responder_auth_key, HMAC_KEY_SIZE);
        }
        
        outbound_sa.selector = TrafficSelector2::fromCIDR("10.0.0.0/24", "192.168.50.0/24");
        
        sad.addEntry(outbound_sa);
        std::cout << "[SAD] Added OUTBOUND SA: SPI=0x" << std::hex << my_outbound_spi << std::dec << std::endl;
        
        // ========================================================================
        // 5. Create Inbound SA (for packets I receive)
        // ========================================================================
        SADEntry inbound_sa;
        inbound_sa.spi = my_inbound_spi;
        inbound_sa.dst_addr = inet_addr(local_addr.c_str());
        inbound_sa.protocol = ESP_PROTOCOL;
        inbound_sa.mode = SA_MODE_TUNNEL;
        inbound_sa.state = SA_STATE_MATURE;
        inbound_sa.tunnel_src = inet_addr(remote_addr.c_str());
        inbound_sa.tunnel_dst = inet_addr(local_addr.c_str());
        
        // My inbound SA uses PEER's keys (to decrypt what they send)
        if (is_initiator) {
            // I'm initiator, so I decrypt with responder's keys
            memcpy(inbound_sa.encryption_key, responder_enc_key, AES_KEY_SIZE);
            memcpy(inbound_sa.authentication_key, responder_auth_key, HMAC_KEY_SIZE);
        } else {
            // I'm responder, so I decrypt with initiator's keys
            memcpy(inbound_sa.encryption_key, initiator_enc_key, AES_KEY_SIZE);
            memcpy(inbound_sa.authentication_key, initiator_auth_key, HMAC_KEY_SIZE);
        }
        
        inbound_sa.selector = TrafficSelector2::fromCIDR("192.168.50.0/24", "10.0.0.0/24");
        
        sad.addEntry(inbound_sa);
        std::cout << "[SAD] Added INBOUND SA: SPI=0x" << std::hex << my_inbound_spi << std::dec << std::endl;
        
        // ========================================================================
        // 6. Create SPD entries
        // ========================================================================
        TrafficSelector2 ts_to_lan = TrafficSelector2::fromCIDR("10.0.0.0/24", "192.168.50.0/24");
        TrafficSelector2 ts_from_lan = TrafficSelector2::fromCIDR("192.168.50.0/24", "10.0.0.0/24");
        

        if(is_initiator){
            // Outbound policy: protect traffic going to LAN
            // voi client 0x111111111  : traffic 10 -> 192
            // voi server 0x222222222  : traffic 10 -> 192
            uint32_t spd_out = spd.addEntry(ts_to_lan, SPD_PROTECT, my_outbound_spi, 100);
            std::cout << "[SPD] Outbound policy " << spd_out << " -> SPI 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
            
            // Inbound policy: expect protected traffic from LAN
            // voi client 0x222222222  : traffic 192 -> 10
            // voi server 0x111111111  : traffic 192 -> 10
            uint32_t spd_in = spd.addEntry(ts_from_lan, SPD_PROTECT, my_inbound_spi, 100);
            std::cout << "[SPD] Inbound policy " << spd_in << " -> SPI 0x" << std::hex << my_inbound_spi << std::dec << std::endl;
            
            std::cout << "[Security] Configuration complete for " << (is_initiator ? "INITIATOR" : "RESPONDER") << std::endl;
            std::cout << "================================================" << std::endl;
        }else{
            // Outbound policy: protect traffic going to LAN
            // voi client 0x111111111  : traffic 10 -> 192
            // voi server 0x222222222  : traffic 10 -> 192
            uint32_t spd_out = spd.addEntry(ts_from_lan, SPD_PROTECT, my_outbound_spi, 100);
            std::cout << "[SPD] Outbound policy " << spd_out << " -> SPI 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
            
            // Inbound policy: expect protected traffic from LAN
            // voi client 0x222222222  : traffic 192 -> 10
            // voi server 0x111111111  : traffic 192 -> 10
            uint32_t spd_in = spd.addEntry(ts_to_lan, SPD_PROTECT, my_inbound_spi, 100);
            std::cout << "[SPD] Inbound policy " << spd_in << " -> SPI 0x" << std::hex << my_inbound_spi << std::dec << std::endl;
            
            std::cout << "[Security] Configuration complete for " << (is_initiator ? "INITIATOR" : "RESPONDER") << std::endl;
            std::cout << "================================================" << std::endl;
        }
        
        
        return true;
    }

    bool setupSecurityPolicy_VER2(const std::string& local_addr, uint16_t local_p,
                            const std::string& remote_addr, uint16_t remote_p,
                            bool is_initiator, ChildSA chil_sa) {
        std::lock_guard<std::mutex> lock(database_mutex);
        
        std::cout << "[Security] Setting up as " << (is_initiator ? "INITIATOR" : "RESPONDER") << std::endl;
        
        // ========================================================================
        // 1. Setup PAD entry for peer
        // ========================================================================
        PADEntry peer;
        peer.peer_identity = remote_addr;
        peer.auth_method = AUTH_PSK;
        
        // Shared PSK (same on both sides)
        std::vector<uint8_t> psk(32, 0xAA);
        peer.auth_data = psk;
        
        // Allow all traffic from this peer
        TrafficSelector2 allowed_ts = TrafficSelector2::fromCIDR("0.0.0.0/0", "0.0.0.0/0");
        peer.allowed_selectors.push_back(allowed_ts);
        
        uint32_t pad_id = pad.addEntry(peer);
        std::cout << "[PAD] Added peer " << remote_addr << " with ID " << pad_id << std::endl;
        
        // ========================================================================
        // 2. SPIs - CRITICAL: Must be opposite on each side!
        // ========================================================================
        uint32_t my_outbound_spi;
        uint32_t my_inbound_spi;
        
        // Initiator uses these SPIs
        my_outbound_spi = chil_sa.getOutboundSPI();  // I send with this SPI
        my_inbound_spi  = chil_sa.getInboundSPI();  // I receive with this SPI
        
        std::cout << "[Initiator] My outbound SPI: 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
        std::cout << "[Initiator] My inbound SPI:  0x" << std::hex << my_inbound_spi << std::dec << std::endl;
        
        
        // ========================================================================
        // 3. Keys - In production, these come from IKEv2 key derivation
        // ========================================================================
        
        // Base key material (would be DH shared secret in real IKEv2)
        uint8_t key_material[64];
        memset(key_material, 0xCD, 64);
        
        // Derive different keys for initiator and responder
        // Using simple derivation: initiator uses first half, responder uses second half
        uint8_t initiator_enc_key[AES_KEY_SIZE];
        uint8_t initiator_auth_key[HMAC_KEY_SIZE];
        uint8_t responder_enc_key[AES_KEY_SIZE];
        uint8_t responder_auth_key[HMAC_KEY_SIZE];
        
        
        // ========================================================================
        // 4. Create Outbound SA (for packets I send)
        // ========================================================================
        SADEntry outbound_sa;
        outbound_sa.spi = my_outbound_spi;
        outbound_sa.dst_addr = inet_addr(remote_addr.c_str());
        outbound_sa.protocol = ESP_PROTOCOL;
        outbound_sa.udp_encap_src_port = local_p;
        outbound_sa.udp_encap_dst_port = remote_p;
        outbound_sa.mode = SA_MODE_TUNNEL;
        outbound_sa.state = SA_STATE_MATURE;
        outbound_sa.tunnel_src = inet_addr(local_addr.c_str());
        outbound_sa.tunnel_dst = inet_addr(remote_addr.c_str());
        
        // My outbound SA uses MY keys (initiator or responder keys based on role)
        std::copy(chil_sa.outboundEncKey().begin(), chil_sa.outboundEncKey().begin() + 32, initiator_enc_key);
        memcpy(outbound_sa.encryption_key, initiator_enc_key, AES_KEY_SIZE);
        std::copy(chil_sa.outboundAuthKey().begin(), chil_sa.outboundAuthKey().begin() + 32, initiator_auth_key);
        memcpy(outbound_sa.authentication_key, initiator_auth_key, HMAC_KEY_SIZE);

        outbound_sa.selector = TrafficSelector2::fromCIDR("10.0.0.0/24", "192.168.50.0/24");
        
        sad.addEntry(outbound_sa);
        std::cout << "[SAD] Added OUTBOUND SA: SPI=0x" << std::hex << my_outbound_spi << std::dec << std::endl;
        
        // ========================================================================
        // 5. Create Inbound SA (for packets I receive)
        // ========================================================================
        SADEntry inbound_sa;
        inbound_sa.spi = my_inbound_spi;
        inbound_sa.dst_addr = inet_addr(local_addr.c_str());
        inbound_sa.protocol = ESP_PROTOCOL;
        inbound_sa.mode = SA_MODE_TUNNEL;
        inbound_sa.state = SA_STATE_MATURE;
        inbound_sa.tunnel_src = inet_addr(remote_addr.c_str());
        inbound_sa.tunnel_dst = inet_addr(local_addr.c_str());
        
        // My inbound SA uses PEER's keys (to decrypt what they send)
        std::copy(chil_sa.inboundEncKey().begin(), chil_sa.inboundEncKey().begin() + 32, responder_enc_key);
        memcpy(inbound_sa.encryption_key, responder_enc_key, AES_KEY_SIZE);

        std::copy(chil_sa.inboundAuthKey().begin(), chil_sa.inboundAuthKey().begin() + 32, responder_auth_key);
        memcpy(inbound_sa.authentication_key, responder_auth_key, HMAC_KEY_SIZE);
    
        
        inbound_sa.selector = TrafficSelector2::fromCIDR("192.168.50.0/24", "10.0.0.0/24");
        
        sad.addEntry(inbound_sa);
        std::cout << "[SAD] Added INBOUND SA: SPI=0x" << std::hex << my_inbound_spi << std::dec << std::endl;
        
        // ========================================================================
        // 6. Create SPD entries
        // ========================================================================
        TrafficSelector2 ts_to_lan = TrafficSelector2::fromCIDR("10.0.0.0/24", "192.168.50.0/24");
        TrafficSelector2 ts_from_lan = TrafficSelector2::fromCIDR("192.168.50.0/24", "10.0.0.0/24");
        

        if(is_initiator){
            // Outbound policy: protect traffic going to LAN
            // voi client 0x111111111  : traffic 10 -> 192
            // voi server 0x222222222  : traffic 10 -> 192
            uint32_t spd_out = spd.addEntry(ts_to_lan, SPD_PROTECT, my_outbound_spi, 100);
            std::cout << "[SPD] Outbound policy " << spd_out << " -> SPI 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
            
            // Inbound policy: expect protected traffic from LAN
            // voi client 0x222222222  : traffic 192 -> 10
            // voi server 0x111111111  : traffic 192 -> 10
            uint32_t spd_in = spd.addEntry(ts_from_lan, SPD_PROTECT, my_inbound_spi, 100);
            std::cout << "[SPD] Inbound policy " << spd_in << " -> SPI 0x" << std::hex << my_inbound_spi << std::dec << std::endl;
            
            std::cout << "[Security] Configuration complete for " << (is_initiator ? "INITIATOR" : "RESPONDER") << std::endl;
            std::cout << "================================================" << std::endl;
        }else{
            // Outbound policy: protect traffic going to LAN
            // voi client 0x111111111  : traffic 10 -> 192
            // voi server 0x222222222  : traffic 10 -> 192
            uint32_t spd_out = spd.addEntry(ts_from_lan, SPD_PROTECT, my_outbound_spi, 100);
            std::cout << "[SPD] Outbound policy " << spd_out << " -> SPI 0x" << std::hex << my_outbound_spi << std::dec << std::endl;
            
            // Inbound policy: expect protected traffic from LAN
            // voi client 0x222222222  : traffic 192 -> 10
            // voi server 0x111111111  : traffic 192 -> 10
            uint32_t spd_in = spd.addEntry(ts_to_lan, SPD_PROTECT, my_inbound_spi, 100);
            std::cout << "[SPD] Inbound policy " << spd_in << " -> SPI 0x" << std::hex << my_inbound_spi << std::dec << std::endl;
            
            std::cout << "[Security] Configuration complete for " << (is_initiator ? "INITIATOR" : "RESPONDER") << std::endl;
            std::cout << "================================================" << std::endl;
        }
        
        
        return true;
    }

    
    std::vector<uint8_t> encryptAES(const std::vector<uint8_t>& plaintext, 
                                   const uint8_t* key, 
                                   const uint8_t* iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};
        
        std::vector<uint8_t> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
        int len, ciphertext_len;
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        ciphertext_len = len;
        
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    std::vector<uint8_t> decryptAES(const std::vector<uint8_t>& ciphertext, 
                                   const uint8_t* key, 
                                   const uint8_t* iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};
        
        std::vector<uint8_t> plaintext(ciphertext.size());
        int len, plaintext_len;
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        plaintext_len = len;
        
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintext_len);
        return plaintext;
    }

    std::vector<uint8_t> calculateHMAC(const std::vector<uint8_t>& data, const uint8_t* key) {
        unsigned int hmac_len;
        uint8_t hmac_full[SHA256_DIGEST_LENGTH];

        HMAC(EVP_sha256(), key, HMAC_KEY_SIZE,
            data.data(), data.size(),
            hmac_full, &hmac_len);

        return std::vector<uint8_t>(hmac_full, hmac_full + ESP_AUTH_SIZE);
    }

    bool verifyHMAC(const std::vector<uint8_t>& data, 
                   const std::vector<uint8_t>& received_hmac, 
                   const uint8_t* key) {
        auto calculated_hmac = calculateHMAC(data, key);
        return calculated_hmac == received_hmac;
    }

    std::vector<uint8_t> applyPadding(const std::vector<uint8_t>& data, uint8_t next_header) {
        size_t total_size = data.size() + sizeof(ESPTrailer);
        size_t padding_needed = AES_BLOCK_SIZE - (total_size % AES_BLOCK_SIZE);
        if (padding_needed == AES_BLOCK_SIZE) padding_needed = 0;
        
        std::vector<uint8_t> padded_data = data;
        
        for (size_t i = 0; i < padding_needed; i++) {
            padded_data.push_back(static_cast<uint8_t>(i + 1));
        }
        
        ESPTrailer trailer;
        trailer.padding_length = static_cast<uint8_t>(padding_needed);
        trailer.next_header = next_header;
        
        padded_data.insert(padded_data.end(), 
                          reinterpret_cast<uint8_t*>(&trailer), 
                          reinterpret_cast<uint8_t*>(&trailer) + sizeof(ESPTrailer));
        
        return padded_data;
    }

    std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data, uint8_t& next_header) {
        if (data.size() < sizeof(ESPTrailer)) return {};
        
        size_t trailer_offset = data.size() - sizeof(ESPTrailer);
        const ESPTrailer* trailer = reinterpret_cast<const ESPTrailer*>(data.data() + trailer_offset);
        
        next_header = trailer->next_header;
        uint8_t padding_length = trailer->padding_length;
        
        if (padding_length >= data.size() - sizeof(ESPTrailer)) return {};
        
        size_t payload_size = data.size() - sizeof(ESPTrailer) - padding_length;
        return std::vector<uint8_t>(data.begin(), data.begin() + payload_size);
    }

    std::vector<uint8_t> encapsulateESP(const std::vector<uint8_t>& payload,
                                       SADEntry* sa,
                                       uint8_t next_header = IPPROTO_IP) {
        if (!sa || sa->state != SA_STATE_MATURE) {
            std::cerr << "Invalid or inactive SA" << std::endl;
            return {};
        }
        //std::cerr << "Encrypt packet! SPI: 0x" << std::hex << sa->spi << std::endl;
        // Check if SA needs rekey
        if (sa->needsRekey()) {
            std::cout << "[WARNING] SA needs rekey: " << sa->toString() << std::endl;
        }
        
        sa->sequence_number++;
        
        ESPHeader esp_header;
        esp_header.spi = htonl(sa->spi);
        esp_header.sequence = htonl(sa->sequence_number);
        
        auto padded_payload = applyPadding(payload, next_header);
        
        uint8_t iv[AES_BLOCK_SIZE];
        if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
            std::cerr << "Failed to generate IV" << std::endl;
            return {};
        }
        
        auto encrypted_payload = encryptAES(padded_payload, sa->encryption_key, iv);
        if (encrypted_payload.empty()) {
            std::cerr << "Encryption failed" << std::endl;
            return {};
        }
        
        std::vector<uint8_t> esp_packet;
        esp_packet.insert(esp_packet.end(), 
                         reinterpret_cast<uint8_t*>(&esp_header),
                         reinterpret_cast<uint8_t*>(&esp_header) + sizeof(ESPHeader));
        esp_packet.insert(esp_packet.end(), iv, iv + AES_BLOCK_SIZE);
        esp_packet.insert(esp_packet.end(), encrypted_payload.begin(), encrypted_payload.end());
        
        auto hmac = calculateHMAC(esp_packet, sa->authentication_key);
        esp_packet.insert(esp_packet.end(), hmac.begin(), hmac.end());
        
        sa->updateStats(esp_packet.size());
        packets_encrypted++;
        
        return esp_packet;
    }

    std::vector<uint8_t> decapsulateESP(const std::vector<uint8_t>& esp_packet, uint8_t& next_header) {
        if (esp_packet.size() < sizeof(ESPHeader) + AES_BLOCK_SIZE + ESP_AUTH_SIZE) {
            packets_dropped++;
            return {};
        }
        
        const ESPHeader* esp_header = reinterpret_cast<const ESPHeader*>(esp_packet.data());
        uint32_t spi = ntohl(esp_header->spi);
        uint32_t seq = ntohl(esp_header->sequence);
        
        SADEntry* sa = sad.lookup(spi);
        if (!sa || sa->state != SA_STATE_MATURE) {
            std::cerr << "Invalid or inactive inbound SA for SPI: 0x" 
                     << std::hex << spi << std::dec << std::endl;
            packets_dropped++;
            return {};
        }
        
        //Anti-replay check
        if (!sa->checkReplayWindow(seq)) {
            std::cerr << "Replay attack detected! SPI: 0x" << std::hex << spi 
                     << " Seq: " << seq << std::dec << std::endl;
            packets_dropped++;
            return {};
        }
        
        size_t payload_size = esp_packet.size() - ESP_AUTH_SIZE;
        std::vector<uint8_t> packet_for_auth(esp_packet.begin(), esp_packet.begin() + payload_size);
        std::vector<uint8_t> received_hmac(esp_packet.end() - ESP_AUTH_SIZE, esp_packet.end());
        
        if (!verifyHMAC(packet_for_auth, received_hmac, sa->authentication_key)) {
            std::cerr << "HMAC verification failed" << std::endl;
            packets_dropped++;
            return {};
        }
        
        const uint8_t* iv = esp_packet.data() + sizeof(ESPHeader);
        size_t encrypted_payload_size = payload_size - sizeof(ESPHeader) - AES_BLOCK_SIZE;
        std::vector<uint8_t> encrypted_payload(
            esp_packet.begin() + sizeof(ESPHeader) + AES_BLOCK_SIZE,
            esp_packet.begin() + sizeof(ESPHeader) + AES_BLOCK_SIZE + encrypted_payload_size
        );
        
        auto decrypted_payload = decryptAES(encrypted_payload, sa->encryption_key, iv);
        if (decrypted_payload.empty()) {
            std::cerr << "Decryption failed" << std::endl;
            packets_dropped++;
            return {};
        }
        
        auto original_payload = removePadding(decrypted_payload, next_header);
        if (original_payload.empty()) {
            std::cerr << "Padding removal failed" << std::endl;
            packets_dropped++;
            return {};
        }
        
        sa->updateStats(original_payload.size());
        packets_decrypted++;
        
        return original_payload;
    }

    bool sendESPPacket(const std::vector<uint8_t>& esp_packet, 
                      const std::string& remote_ip, uint16_t remote_port) {
        
        std::cout<<"Remote ip: "<<remote_ip<<std::endl;
        struct sockaddr_in remote_addr;
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = inet_addr(remote_ip.c_str());
        remote_addr.sin_port = htons(remote_port);
        
        // Add NAT-T non-ESP marker
        std::vector<uint8_t> nat_t_packet(4, 0);
        nat_t_packet.insert(nat_t_packet.end(), esp_packet.begin(), esp_packet.end());
        
        ssize_t sent = sendto(udp_socket, nat_t_packet.data(), nat_t_packet.size(), 0,
                             (struct sockaddr*)&remote_addr, sizeof(remote_addr));
        
        if (sent < 0) {
            std::cerr << "Failed to send ESP packet" << std::endl;
            return false;
        }
        
        packets_sent++;
        return true;
    }

    void tunReadLoop() {
        uint8_t buffer[MAX_PACKET_SIZE];
        
        while (running) {
            ssize_t packet_size = read(tun_fd, buffer, sizeof(buffer));
            if (packet_size < 0) {
                if (running) {
                    std::cerr << "Error reading from TUN interface" << std::endl;
                }
                continue;
            }
            
            if (packet_size == 0 || packet_size < sizeof(IPHeader)) continue;
            
            const IPHeader* ip_hdr = reinterpret_cast<const IPHeader*>(buffer);
            
             // Extract 5-tuple for SPD lookup
            uint32_t src_ip = ip_hdr->src_addr;
            uint32_t dst_ip = ip_hdr->dst_addr;
            uint8_t protocol = ip_hdr->protocol;
            uint16_t src_port = 0, dst_port = 0;

            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

            // ---- In ra thông tin ----
            std::cout << "####-------------------------------" << std::endl;
            std::cout << "Source IP   : " << src_ip_str << std::endl;
            std::cout << "Destination : " << dst_ip_str << std::endl;
            std::cout << "Protocol    : " << static_cast<int>(protocol) << std::endl;
            std::cout << "Source Port : " << src_port << std::endl;
            std::cout << "Dest Port   : " << dst_port << std::endl;
            std::cout << "####-------------------------------" << std::endl;


            PacketInfo pkt = extractPacketInfo(buffer, packet_size);
            std::cout << "[OUTBOUND] " << inet_ntoa({pkt.src_ip}) << ":" << pkt.src_port
                  << " -> " << inet_ntoa({pkt.dst_ip}) << ":" << pkt.dst_port
                  << " proto:" << (int)pkt.protocol << std::endl;
        

            
            std::lock_guard<std::mutex> lock(database_mutex);
            SPDEntry* policy = spd.lookupOutbound(pkt.src_ip, pkt.dst_ip, 
                                                pkt.src_port, pkt.dst_port, 
                                                pkt.protocol);
            
            if (!policy) {
                std::cout << "[SPD] No policy found, dropping packet" << std::endl;
                packets_dropped++;
                continue;
            }
            
            policy->updateStats(packet_size);
            
            if (policy->action == SPD_BYPASS) {
                std::cout << "[SPD] BYPASS policy, sending in clear" << std::endl;
                // Send without IPsec (not implemented in this example)
                continue;
            } else if (policy->action == SPD_DISCARD) {
                std::cout << "[SPD] DISCARD policy, dropping packet" << std::endl;
                packets_dropped++;
                continue;
            }
            
            // SPD_PROTECT: Find SA
            TrafficSelector2 ts = policy->selector;
            SADEntry* sa = sad.lookup(policy->sa_bundle_id); 
            
            if (!sa) {
                std::cerr << "[SAD] No SA for dst:" << inet_ntoa({pkt.dst_ip}) << std::endl;
                packets_dropped++;
                continue;
            }
            
            std::cout << "[SAD] Using SPI: 0x" << std::hex << sa->spi << std::dec << std::endl;
            // Check SA state
            if (sa->isExpired()) {
                std::cerr << "[SAD] SA expired!" << std::endl;
                packets_dropped++;
                continue;
            }
            
            if (sa->needsRekey()) {
                std::cout << "[SAD] WARNING: SA needs rekey" << std::endl;
                // Continue but log warning
            }
            
            std::vector<uint8_t> ip_packet(buffer, buffer + packet_size);
            auto esp_packet = encapsulateESP(ip_packet, sa, IPPROTO_IP);
            
            if (!esp_packet.empty()) {
                struct in_addr addr;
                addr.s_addr = sa->dst_addr;
                std::string remote_ip = inet_ntoa(addr);
                
                sendESPPacket(esp_packet, remote_ip, sa->udp_encap_dst_port);
                
                char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip_str, INET_ADDRSTRLEN);
                
                std::cout << "[OUTBOUND] " << src_ip_str << " -> " << dst_ip_str 
                         << " via SPI 0x" << std::hex << sa->spi << std::dec << std::endl;
            }
        }
    }

    void writeToTun(const std::vector<uint8_t>& packet) {
        if (tun_fd < 0) return;
        
        ssize_t written = write(tun_fd, packet.data(), packet.size());
        if (written < 0) {
            std::cerr << "Error writing to TUN interface" << std::endl;
        }
    }

    void receiveLoop() {
        uint8_t buffer[MAX_PACKET_SIZE];
        struct sockaddr_in remote_addr;
        socklen_t addr_len = sizeof(remote_addr);
        
        while (running) {
            ssize_t received = recvfrom(udp_socket, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&remote_addr, &addr_len);
            
            if (received < 0) {
                if (running) {
                    std::cerr << "Failed to receive packet" << std::endl;
                }
                continue;
            }
            
            packets_received++;
            
            if (received < 4 || memcmp(buffer, "\x00\x00\x00\x00", 4) != 0) {
                packets_dropped++;
                continue;
            }
            std::cout<<"Co goi tin ne ---------------------------"<<std::endl;
            std::vector<uint8_t> esp_packet(buffer + 4, buffer + received);

            const ESPHeader* esp_hdr = reinterpret_cast<const ESPHeader*>(esp_packet.data());
            uint32_t spi = ntohl(esp_hdr->spi);
            
            std::cout << "[INBOUND] Received ESP packet, SPI: 0x" << std::hex << spi << std::dec << std::endl;
            uint8_t next_header;
            auto decrypted_payload = decapsulateESP(esp_packet, next_header);
            
            if (!decrypted_payload.empty()) {
                processDecryptedPacket(decrypted_payload, next_header, spi);
            }
        }
    }

    virtual void processDecryptedPacket(const std::vector<uint8_t>& payload, 
                                    uint8_t next_header,
                                    uint32_t spi) {
        if (next_header != IPPROTO_IP || payload.size() < sizeof(IPHeader)) {
            packets_dropped++;
            return;
        }
        
        // Extract packet info
        PacketInfo pkt = extractPacketInfo(payload.data(), payload.size());
        
        std::cout << "[INBOUND] Inner packet: " << inet_ntoa({pkt.src_ip}) << ":" << pkt.src_port
                << " -> " << inet_ntoa({pkt.dst_ip}) << ":" << pkt.dst_port << std::endl;
        
        // ✅ Inbound SPD check với SPI
        std::lock_guard<std::mutex> lock(database_mutex);
        SPDEntry* policy = spd.lookupInbound(pkt.src_ip, pkt.dst_ip,
                                            pkt.src_port, pkt.dst_port,
                                            pkt.protocol, spi);
        
        if (!policy) {
            std::cout << "[SPD] Inbound: No matching policy, DROP" << std::endl;
            packets_dropped++;
            return;
        }
        
        // ✅ Verify SPI matches policy's expected SA
        if (policy->action != SPD_PROTECT) {
            std::cout << "[SPD] Policy not PROTECT, DROP" << std::endl;
            packets_dropped++;
            return;
        }
        
        // In production: verify spi belongs to policy->sa_bundle_id
        SADEntry* sa = sad.lookup(spi);
        if (!sa) {
            std::cout << "[SAD] SPI not found in SAD, DROP" << std::endl;
            packets_dropped++;
            return;
        }
        
        policy->updateStats(payload.size());
        
        std::cout << "[INBOUND] Policy matched, forwarding to TUN" << std::endl;
        writeToTun(payload);
    }

    bool start() {
        if (running) return true;
        
        running = true;
        receive_thread = std::thread(&ESPVPNTunnel::receiveLoop, this);
        tun_thread = std::thread(&ESPVPNTunnel::tunReadLoop, this);
        
        std::cout << "ESP VPN Tunnel started" << std::endl;
        return true;
    }

    void stop() {
        if (!running) return;
        
        running = false;
        if (receive_thread.joinable()) {
            receive_thread.join();
        }
        if (tun_thread.joinable()) {
            tun_thread.join();
        }
        
        std::cout << "ESP VPN Tunnel stopped" << std::endl;
    }

    void printStatistics() {
        std::cout << "\n=== ESP VPN Statistics ===" << std::endl;
        std::cout << "Packets sent: " << packets_sent << std::endl;
        std::cout << "Packets received: " << packets_received << std::endl;
        std::cout << "Packets encrypted: " << packets_encrypted << std::endl;
        std::cout << "Packets decrypted: " << packets_decrypted << std::endl;
        std::cout << "Packets dropped: " << packets_dropped << std::endl;
    }

    void printDatabases() {
        std::lock_guard<std::mutex> lock(database_mutex);
        spd.printAll();
        sad.printAll();
        pad.printAll();
    }

    void cleanupExpiredSAs() {
        std::lock_guard<std::mutex> lock(database_mutex);
        sad.cleanupExpired();
    }
};

class ESPVPNClient : public ESPVPNTunnel {
public:
    ESPVPNClient() : ESPVPNTunnel(false) {}


    void interactiveMode() {
        std::string command;
        std::cout << "\n=== Interactive Mode ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  stats              - Show statistics" << std::endl;
        std::cout << "  databases          - Show SPD/SAD/PAD" << std::endl;
        std::cout << "  cleanup            - Cleanup expired SAs" << std::endl;
        std::cout << "  test <ip>          - Test connectivity to IP" << std::endl;
        std::cout << "  quit               - Exit interactive mode" << std::endl;
        
        while (std::cin >> command && command != "quit") {
            if (command == "stats") {
                printStatistics();
            } else if (command == "databases") {
                printDatabases();
            } else if (command == "cleanup") {
                cleanupExpiredSAs();
                std::cout << "Expired SAs cleaned up" << std::endl;
            } else if (command == "test") {
                std::string ip;
                if (std::cin >> ip) {
                    std::cout << "Testing connectivity to " << ip << std::endl;
                    std::string cmd = "ping -c 3 " + ip;
                    system(cmd.c_str());
                }
            } else {
                std::cout << "Unknown command: " << command << std::endl;
            }
            
            std::cout << "> ";
        }
    }
};

class ESPVPNServer : public ESPVPNTunnel {
public:
    ESPVPNServer() : ESPVPNTunnel(true) {}
    
};

// Network testing and demonstration
int main(int argc, char* argv[]) {
    std::cout << "IKEv2 Network Protocol Implementation\n";
    std::cout << "====================================\n";
    
    
    std::string mode = argv[1];
    
    try {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        std::unique_ptr<ESPVPNTunnel> vpn;

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
                
                vpn = std::make_unique<ESPVPNServer>();
                if (!vpn->initialize("0.0.0.0", 4500)) {
                    std::cerr << "Failed to init ESP server\n";
                    return 1;
                }

                std::string client_ip="192.168.1.19";
                // std::cout << "Enter client IP: ";
                // std::cin >> client_ip;

                // Tạo SA cho ESP với key đã lấy
                ChildSA chil=*responder.getSa()->getFirstChildSA();
                vpn->setupSecurityPolicy_VER2("0.0.0.0", 4500, client_ip, 8082, false, chil);
                vpn->start();

                std::cout << "ESP tunnel running...\n";

                // Keep running to maintain the connection
                // std::cout << "Connection established. Press Ctrl+C to exit.\n";
                // while (responder.isEstablished()) {
                //     std::this_thread::sleep_for(std::chrono::seconds(1));
                // }

                // vòng lặp xử lý
                std::string input;
                while (std::getline(std::cin, input)) {
                    if (input == "q") break;
                    else if (input == "stats") vpn->printStatistics();
                }
            } else {
                std::cerr << "Failed to establish connection" << std::endl;
                return 1;
            }
            
        } else if (mode == "initiator") {
            
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

                auto client = std::make_unique<ESPVPNClient>();
                vpn = std::move(client);

                if (!vpn->initialize("0.0.0.0", 8082)) {
                    std::cerr << "Failed to init ESP client\n";
                    return 1;
                }
                ChildSA chil=*initiator.getSa()->getFirstChildSA();
                vpn->setupSecurityPolicy_VER2("0.0.0.0", 8082, peer_ip, 4500, true, chil);
                vpn->start();

                std::cout << "ESP client tunnel up\n";
                ESPVPNClient* client_ptr = static_cast<ESPVPNClient*>(vpn.get());
                client_ptr->interactiveMode();
                
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
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
        
    return 0;
}