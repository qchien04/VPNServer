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
//g++ -std=c++14 -O2 -Wall -Wextra -o main main.cpp -lssl -lcrypto -lpthread
// sudo ./main responder 8080 MySecretPSK123
// sudo ./main initiator 192.168.2.18 8080 8081 MySecretPSK123
// scp /home/chien/vpn/main chien@192.168.2.19:/home/chien/
// scp /home/chien/vpn/main chien@172.31.213.48:/home/chien/
// sudo ./main initiator 172.31.213.79 8080 8081 MySecretPSK123
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


// ESP Protocol Constants
#define ESP_PROTOCOL 50
#define UDP_ESP_PORT 4500  // NAT-T port
#define MAX_PACKET_SIZE 10000
#define ESP_HEADER_SIZE 8
#define ESP_TRAILER_MIN_SIZE 2
#define ESP_AUTH_SIZE 16  // HMAC-SHA256
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define HMAC_KEY_SIZE 32

// ESP Packet Structure
struct ESPHeader {
    uint32_t spi;          // Security Parameter Index
    uint32_t sequence;     // Sequence Number
} __attribute__((packed));

struct ESPTrailer {
    uint8_t padding_length;
    uint8_t next_header;
} __attribute__((packed));

// Enhanced Security Association Structure with networking info
struct SecurityAssociation {
    // Identity
    std::string sa_name;           // Unique identifier for this SA
    uint32_t spi;
    bool is_outbound;
    
    // Networking information
    std::string local_ip;
    std::string remote_ip;
    uint16_t local_port;
    uint16_t remote_port;
    
    // Cryptographic material
    uint8_t encryption_key[AES_KEY_SIZE];
    uint8_t authentication_key[HMAC_KEY_SIZE];
    EncryptionAlgorithm encryption_algo;
    IntegrityAlgorithm auth_algo;
    
    // State
    uint32_t sequence_number;
    bool active;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_used;
    
    // Statistics
    uint64_t packets_processed;
    uint64_t bytes_processed;
    
    SecurityAssociation() : 
        spi(0), 
        is_outbound(true),
        local_port(0),
        remote_port(0),
        sequence_number(0),
        active(true),
        packets_processed(0),
        bytes_processed(0) {
        
        encryption_algo = EncryptionAlgorithm::AES_CBC_256;
        auth_algo = IntegrityAlgorithm::AUTH_HMAC_SHA256_128;
        created_at = std::chrono::system_clock::now();
        last_used = created_at;
    }
    
    void updateLastUsed() {
        last_used = std::chrono::system_clock::now();
    }
    
    // Get socket address structure
    struct sockaddr_in getRemoteAddr() const {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr(remote_ip.c_str());
        addr.sin_port = htons(remote_port);
        return addr;
    }
};

// IP Header Structure
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

// UDP Header
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

class ESPVPNTunnel {
protected:
    // Changed: Use remote_ip as key for outbound SAs
    std::map<std::string, std::shared_ptr<SecurityAssociation>> outbound_sas;
    // Keep SPI as key for inbound SAs (since we receive based on SPI)
    std::map<uint32_t, std::shared_ptr<SecurityAssociation>> inbound_sas;
    std::mutex sa_mutex;
    
    int raw_socket;
    int udp_socket;
    int tun_fd;
    bool is_server;
    std::string tunnel_ip;
    std::string lan_network;
    
    // Threading
    std::thread receive_thread;
    std::thread tun_thread;
    bool running;
    
    // Statistics
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

    void printNetworkStatus() {
        std::cout << "\n=== Network Configuration Status ===" << std::endl;
        
        std::ifstream forward_file("/proc/sys/net/ipv4/ip_forward");
        if (forward_file.is_open()) {
            std::string forward_status;
            forward_file >> forward_status;
            std::cout << "IP Forwarding: " << (forward_status == "1" ? "Enabled" : "Disabled") << std::endl;
        }
        
        std::cout << "\nTUN Interface Status:" << std::endl;
        system("ip addr show tun1 2>/dev/null || echo 'TUN interface not found'");
        
        std::cout << "\nRelevant Routes:" << std::endl;
        system("ip route show | grep -E '(10.0.0|192.168.50|tun1)' || echo 'No relevant routes found'");
        
        if (is_server) {
            std::cout << "\nNAT Rules:" << std::endl;
            system("iptables -t nat -L POSTROUTING -n --line-numbers 2>/dev/null | grep -E '(10.0.0|192.168.50)' || echo 'No NAT rules found'");
            
            std::cout << "\nForward Rules:" << std::endl;
            system("iptables -L FORWARD -n --line-numbers 2>/dev/null | grep -E '(10.0.0|192.168.50)' || echo 'No forward rules found'");
        }
        
        std::cout << "==================================\n" << std::endl;
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
            std::cout << "Configuring server networking..." << std::endl;
            
            cmd = "ip addr add " + tunnel_ip + "/24 dev " + tun_name;
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            cmd = "ip link set " + tun_name + " up";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            std::cout << "Enabling IP forwarding..." << std::endl;
            system("echo 1 > /proc/sys/net/ipv4/ip_forward");
            
            std::string main_interface = getMainInterface();
            std::string lan_interface = "ens37";
            std::cout << "Main interface detected: " << main_interface << std::endl;
            std::cout << "LAN interface: " << lan_interface << std::endl;
            
            system("iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -d 192.168.50.0/24 -j MASQUERADE 2>/dev/null || true");
            system("iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true");
            system("iptables -D FORWARD -s 10.0.0.0/24 -d 192.168.50.0/24 -j ACCEPT 2>/dev/null || true");
            system("iptables -D FORWARD -s 192.168.50.0/24 -d 10.0.0.0/24 -j ACCEPT 2>/dev/null || true");
            
            cmd = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 192.168.50.0/24 -o " + lan_interface + " -j MASQUERADE";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            if (main_interface != lan_interface) {
                cmd = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o " + main_interface + " -j MASQUERADE";
                std::cout << "Executing: " << cmd << std::endl;
                system(cmd.c_str());
            }
            
            cmd = "iptables -A FORWARD -s 10.0.0.0/24 -d 192.168.50.0/24 -j ACCEPT";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            cmd = "iptables -A FORWARD -s 192.168.50.0/24 -d 10.0.0.0/24 -j ACCEPT";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            cmd = "iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            cmd = "ip route add 10.0.0.0/24 dev " + tun_name + " 2>/dev/null || true";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            std::cout << "Server network configuration completed." << std::endl;
            
        } else {
            std::cout << "Configuring client networking..." << std::endl;
            
            cmd = "ip addr add " + tunnel_ip + "/24 dev " + tun_name;
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            cmd = "ip link set " + tun_name + " up";
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            cmd = "ip route del 192.168.50.0/24 2>/dev/null || true";
            system(cmd.c_str());
            
            cmd = "ip route add 192.168.50.0/24 via 10.0.0.1 dev " + tun_name;
            std::cout << "Executing: " << cmd << std::endl;
            system(cmd.c_str());
            
            std::cout << "Client network configuration completed." << std::endl;
        }
        
        printNetworkStatus();
        
        return true;
    }

    uint16_t calculateIPChecksum(void* vdata, size_t length) {
        char* data = (char*)vdata;
        uint32_t acc = 0xffff;
        
        for (size_t i = 0; i + 1 < length; i += 2) {
            uint16_t word;
            memcpy(&word, data + i, 2);
            acc += ntohs(word);
            if (acc > 0xffff) {
                acc -= 0xffff;
            }
        }
        
        if (length & 1) {
            uint16_t word = 0;
            memcpy(&word, data + length - 1, 1);
            acc += ntohs(word);
            if (acc > 0xffff) {
                acc -= 0xffff;
            }
        }
        
        return htons(~acc);
    }

    bool initialize(const std::string& local_addr, uint16_t local_p) {
        if (!createTunInterface()) {
            std::cerr << "Failed to create TUN interface" << std::endl;
            return false;
        }
        
        raw_socket = socket(AF_INET, SOCK_RAW, ESP_PROTOCOL);
        if (raw_socket < 0) {
            std::cerr << "Failed to create raw socket for ESP" << std::endl;
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

    // Create SA with full networking information
    std::string createSA_VER2(const std::string& local_addr, uint16_t local_p,
                        const std::string& remote_addr, uint16_t remote_p,ChildSA child_sa,
                        bool outbound = true) {
        auto sa = std::make_shared<SecurityAssociation>();
        
        
        std::lock_guard<std::mutex> lock(sa_mutex);
        if (outbound) {
            // Use remote endpoint as key for outbound
            std::string key = remote_addr + ":" + std::to_string(remote_p);
            // Set networking information
            sa->local_ip = local_addr;
            sa->local_port = local_p;
            sa->remote_ip = remote_addr;
            sa->remote_port = remote_p;
            sa->is_outbound = outbound;
            
            // Generate unique SA name
            sa->sa_name = (outbound ? "OUT_" : "IN_") + remote_addr + ":" + std::to_string(remote_p);
            
            // Fixed SPI for testing
            sa->spi = child_sa.getOutboundSPI();
            
            memcpy(sa->encryption_key, child_sa.outboundEncKey().data(), AES_KEY_SIZE);
            
            memcpy(sa->authentication_key, child_sa.outboundAuthKey().data(), HMAC_KEY_SIZE);
            outbound_sas[key] = sa;
            std::cout << "Created outbound SA: " << sa->sa_name 
                     << " (key: " << key << ")" << std::endl;
        } else {
            sa->local_ip = local_addr;
            sa->local_port = local_p;
            sa->remote_ip = remote_addr;
            sa->remote_port = remote_p;
            sa->is_outbound = outbound;
            
            // Generate unique SA name
            sa->sa_name = (outbound ? "OUT_" : "IN_") + remote_addr + ":" + std::to_string(remote_p);
            
            // Fixed SPI for testing
            sa->spi = child_sa.getInboundSPI();
            
            memcpy(sa->encryption_key, child_sa.inboundEncKey().data(), AES_KEY_SIZE);
            
            memcpy(sa->authentication_key, child_sa.inboundAuthKey().data(), HMAC_KEY_SIZE);
            // Use SPI as key for inbound
            inbound_sas[sa->spi] = sa;
            std::cout << "Created inbound SA: " << sa->sa_name 
                     << " (SPI: 0x" << std::hex << sa->spi << std::dec << ")" << std::endl;
        }
        
        return sa->sa_name;
    }

    // Get outbound SA by remote endpoint
    std::shared_ptr<SecurityAssociation> getOutboundSA(const std::string& remote_ip, uint16_t remote_port) {
        std::string key = remote_ip + ":" + std::to_string(remote_port);
        std::lock_guard<std::mutex> lock(sa_mutex);
        auto it = outbound_sas.find(key);
        if (it != outbound_sas.end()) {
            return it->second;
        }
        return nullptr;
    }

    // Get inbound SA by SPI
    std::shared_ptr<SecurityAssociation> getInboundSA(uint32_t spi) {
        std::lock_guard<std::mutex> lock(sa_mutex);
        auto it = inbound_sas.find(spi);
        if (it != inbound_sas.end()) {
            return it->second;
        }
        return nullptr;
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

        std::vector<uint8_t> hmac_128(hmac_full, hmac_full + ESP_AUTH_SIZE);
        return hmac_128;
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

    // Encapsulate with SA that contains all network info
    std::vector<uint8_t> encapsulateESP(const std::vector<uint8_t>& payload,
                                       std::shared_ptr<SecurityAssociation> sa,
                                       uint8_t next_header = IPPROTO_IP) {
        if (!sa || !sa->active) {
            std::cerr << "Invalid or inactive SA" << std::endl;
            return {};
        }
        
        sa->sequence_number++;
        sa->updateLastUsed();
        
        ESPHeader esp_header;
        esp_header.spi = htonl(sa->spi);
        esp_header.sequence = htonl(sa->sequence_number);
        
        auto padded_payload = applyPadding(payload, next_header);
        
        uint8_t iv[AES_BLOCK_SIZE];
        if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
            std::cerr << "Failed to generate IV" << std::endl;
            return {};
        }
        std::cout << "Encryption key: ";
        for (size_t i = 0; i < AES_KEY_SIZE; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(sa->encryption_key[i]);
        }
        std::cout << std::dec << std::endl; 
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
        
        sa->packets_processed++;
        sa->bytes_processed += esp_packet.size();
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
        
        auto sa = getInboundSA(spi);
        if (!sa || !sa->active) {
            std::cerr << "Invalid or inactive inbound SA for SPI: 0x" 
                     << std::hex << spi << std::dec << std::endl;
            packets_dropped++;
            return {};
        }
        
        sa->updateLastUsed();
        
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
        std::cout << "Decryption key: ";
        for (size_t i = 0; i < AES_KEY_SIZE; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(sa->encryption_key[i]);
        }
        std::cout << std::dec << std::endl;

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
        
        sa->packets_processed++;
        sa->bytes_processed += original_payload.size();
        packets_decrypted++;
        
        return original_payload;
    }

    // Send ESP packet using SA's network info
    bool sendESPPacket(const std::vector<uint8_t>& esp_packet, 
                      std::shared_ptr<SecurityAssociation> sa) {
        if (!sa) {
            std::cerr << "Invalid SA for sending" << std::endl;
            return false;
        }
        
        struct sockaddr_in remote_addr = sa->getRemoteAddr();
        
        // Add NAT-T non-ESP marker
        std::vector<uint8_t> nat_t_packet(4, 0);
        nat_t_packet.insert(nat_t_packet.end(), esp_packet.begin(), esp_packet.end());
        
        ssize_t sent = sendto(udp_socket, nat_t_packet.data(), nat_t_packet.size(), 0,
                             (struct sockaddr*)&remote_addr, sizeof(remote_addr));
        
        if (sent < 0) {
            std::cerr << "Failed to send ESP packet to " 
                     << sa->remote_ip << ":" << sa->remote_port << std::endl;
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
            
            if (packet_size == 0) continue;
            
            std::cout << "Read " << packet_size << " bytes from TUN interface" << std::endl;
            
            std::vector<uint8_t> ip_packet(buffer, buffer + packet_size);
            
            // Get destination IP to find the right SA
            std::shared_ptr<SecurityAssociation> sa_to_use = nullptr;
            
            {
                std::lock_guard<std::mutex> lock(sa_mutex);
                // For now, use the first available outbound SA
                // In production, you'd route based on destination IP
                if (!outbound_sas.empty()) {
                    sa_to_use = outbound_sas.begin()->second;
                }
            }
            
            if (sa_to_use) {
                auto esp_packet = encapsulateESP(ip_packet, sa_to_use, IPPROTO_IP);
                if (!esp_packet.empty()) {
                    sendESPPacket(esp_packet, sa_to_use);
                    
                    if (packet_size >= sizeof(IPHeader)) {
                        const IPHeader* ip_hdr = reinterpret_cast<const IPHeader*>(buffer);
                        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip, INET_ADDRSTRLEN);
                        
                        std::cout << "Forwarded packet via " << sa_to_use->sa_name 
                                << ": " << src_ip << " -> " << dst_ip 
                                << " (Protocol: " << static_cast<int>(ip_hdr->protocol) << ")" << std::endl;
                    }
                }
            } else {
                std::cerr << "No outbound SA available" << std::endl;
            }
        }
    }

    void writeToTun(const std::vector<uint8_t>& packet) {
        if (tun_fd < 0) return;
        
        ssize_t written = write(tun_fd, packet.data(), packet.size());
        if (written < 0) {
            std::cerr << "Error writing to TUN interface" << std::endl;
        } else {
            std::cout << "Wrote " << written << " bytes to TUN interface" << std::endl;
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
            
            char remote_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &remote_addr.sin_addr, remote_ip_str, INET_ADDRSTRLEN);
            uint16_t remote_port_val = ntohs(remote_addr.sin_port);
            
            std::cout << "Received " << received << " bytes from " 
                     << remote_ip_str << ":" << remote_port_val << std::endl;
            
            if (received < 4 || memcmp(buffer, "\x00\x00\x00\x00", 4) != 0) {
                std::cerr << "Invalid NAT-T packet format" << std::endl;
                packets_dropped++;
                continue;
            }
            
            std::vector<uint8_t> esp_packet(buffer + 4, buffer + received);
            uint8_t next_header;
            auto decrypted_payload = decapsulateESP(esp_packet, next_header);
            
            if (!decrypted_payload.empty()) {
                processDecryptedPacket(decrypted_payload, next_header);
            }
        }
    }

    virtual void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) {
        std::cout << "Received and decrypted " << payload.size() 
                << " bytes, next header: " << static_cast<int>(next_header) << std::endl;

        if (next_header == IPPROTO_IP && payload.size() >= sizeof(IPHeader)) {
            const IPHeader* ip_header = reinterpret_cast<const IPHeader*>(payload.data());
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_header->src_addr, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->dst_addr, dst_ip, INET_ADDRSTRLEN);

            std::cout << "Decrypted IP packet: " << src_ip << " -> " << dst_ip
                    << " (Protocol: " << static_cast<int>(ip_header->protocol) << ")" << std::endl;
            
            writeToTun(payload);
        } else {
            std::string as_text;
            for (uint8_t byte : payload) {
                if (std::isprint(byte)) {
                    as_text += static_cast<char>(byte);
                } else {
                    as_text += '.';
                }
            }
            std::cout << "Decrypted content: " << as_text << std::endl;
        }
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
        
        std::lock_guard<std::mutex> lock(sa_mutex);
        std::cout << "Active outbound SAs: " << outbound_sas.size() << std::endl;
        std::cout << "Active inbound SAs: " << inbound_sas.size() << std::endl;
    }

    void printSAInfo() {
        std::lock_guard<std::mutex> lock(sa_mutex);
        
        std::cout << "\n=== Outbound Security Associations ===" << std::endl;
        for (const auto& pair : outbound_sas) {
            auto sa = pair.second;
            std::cout << "Key: " << pair.first << std::endl;
            std::cout << "  Name: " << sa->sa_name << std::endl;
            std::cout << "  SPI: 0x" << std::hex << sa->spi << std::dec << std::endl;
            std::cout << "  Local: " << sa->local_ip << ":" << sa->local_port << std::endl;
            std::cout << "  Remote: " << sa->remote_ip << ":" << sa->remote_port << std::endl;
            std::cout << "  Sequence: " << sa->sequence_number << std::endl;
            std::cout << "  Packets: " << sa->packets_processed << std::endl;
            std::cout << "  Bytes: " << sa->bytes_processed << std::endl;
            std::cout << "  Active: " << (sa->active ? "Yes" : "No") << std::endl;
            std::cout << std::endl;
        }
        
        std::cout << "=== Inbound Security Associations ===" << std::endl;
        for (const auto& pair : inbound_sas) {
            auto sa = pair.second;
            std::cout << "SPI: 0x" << std::hex << pair.first << std::dec << std::endl;
            std::cout << "  Name: " << sa->sa_name << std::endl;
            std::cout << "  Local: " << sa->local_ip << ":" << sa->local_port << std::endl;
            std::cout << "  Remote: " << sa->remote_ip << ":" << sa->remote_port << std::endl;
            std::cout << "  Packets: " << sa->packets_processed << std::endl;
            std::cout << "  Bytes: " << sa->bytes_processed << std::endl;
            std::cout << "  Active: " << (sa->active ? "Yes" : "No") << std::endl;
            std::cout << std::endl;
        }
    }
};

class ESPVPNClient : public ESPVPNTunnel {
public:
    ESPVPNClient() : ESPVPNTunnel(false) {}
    
    void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) override {
        std::cout << "[CLIENT] Received " << payload.size() << " bytes" << std::endl;
        ESPVPNTunnel::processDecryptedPacket(payload, next_header);
    }

    void interactiveMode() {
        std::string command;
        std::cout << "\n=== Interactive Mode ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  stats              - Show statistics" << std::endl;
        std::cout << "  sa                 - Show SA information" << std::endl;
        std::cout << "  network            - Show network status" << std::endl;
        std::cout << "  test <ip>          - Test connectivity to IP" << std::endl;
        std::cout << "  quit               - Exit interactive mode" << std::endl;
        
        while (std::cin >> command && command != "quit") {
            if (command == "stats") {
                printStatistics();
            } else if (command == "sa") {
                printSAInfo();
            } else if (command == "network") {
                printNetworkStatus();
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
    
    void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) override {
        std::cout << "[SERVER] Received " << payload.size() << " bytes" << std::endl;
        ESPVPNTunnel::processDecryptedPacket(payload, next_header);
    }
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

                std::string client_ip="172.31.213.48";
                // std::cout << "Enter client IP: ";
                // std::cin >> client_ip;

                // Tạo SA cho ESP với key đã lấy
                ChildSA chil=*responder.getSa()->getFirstChildSA();
                vpn->createSA_VER2("0.0.0.0", 4500, client_ip, 8082, chil, true);
                vpn->createSA_VER2("0.0.0.0", 4500, client_ip, 8082, chil, false);
                vpn->start();

                std::cout << "ESP tunnel running...\n";
                vpn->printSAInfo();

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
                vpn->createSA_VER2("0.0.0.0", 8082, peer_ip, 4500,chil, true);
                vpn->createSA_VER2("0.0.0.0", 8082, peer_ip, 4500, chil,false);
                vpn->start();

                std::cout << "ESP client tunnel up\n";
                vpn->printSAInfo();

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