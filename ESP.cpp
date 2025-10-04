#include <iostream>
//g++ -std=c++17 -o fix fix.cpp -lssl -lcrypto -lpthread
//sudo ./esp_vpn
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <mutex>
#include <random>
#include <cstring>
#include <sstream>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <iomanip>
#include <fstream>
#include <iterator>

#include "common.h"
#include "ChildSA.h"

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
    std::string createSA(const std::string& local_addr, uint16_t local_p,
                        const std::string& remote_addr, uint16_t remote_p,
                        bool outbound = true) {
        auto sa = std::make_shared<SecurityAssociation>();
        
        // Set networking information
        sa->local_ip = local_addr;
        sa->local_port = local_p;
        sa->remote_ip = remote_addr;
        sa->remote_port = remote_p;
        sa->is_outbound = outbound;
        
        // Generate unique SA name
        sa->sa_name = (outbound ? "OUT_" : "IN_") + remote_addr + ":" + std::to_string(remote_p);
        
        // Fixed SPI for testing
        sa->spi = 0x11111111;
        
        // Fixed AES-256 key
        static const uint8_t fixed_key[AES_KEY_SIZE] = {
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
            0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
            0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
        };
        memcpy(sa->encryption_key, fixed_key, AES_KEY_SIZE);
        
        // Fixed HMAC key
        static const uint8_t fixed_hmac[HMAC_KEY_SIZE] = {
            0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
            0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
            0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
            0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
        };
        memcpy(sa->authentication_key, fixed_hmac, HMAC_KEY_SIZE);
        
        std::lock_guard<std::mutex> lock(sa_mutex);
        if (outbound) {
            // Use remote endpoint as key for outbound
            std::string key = remote_addr + ":" + std::to_string(remote_p);
            outbound_sas[key] = sa;
            std::cout << "Created outbound SA: " << sa->sa_name 
                     << " (key: " << key << ")" << std::endl;
        } else {
            // Use SPI as key for inbound
            inbound_sas[sa->spi] = sa;
            std::cout << "Created inbound SA: " << sa->sa_name 
                     << " (SPI: 0x" << std::hex << sa->spi << std::dec << ")" << std::endl;
        }
        
        return sa->sa_name;
    }

    // Create SA with full networking information
    std::string createSA_VER2(const std::string& local_addr, uint16_t local_p,
                        const std::string& remote_addr, uint16_t remote_p,
                        bool outbound = true,ChildSA child_sa) {
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
            sa->spi = child_sa.getOutboundSPI();
            
            memcpy(sa->encryption_key, child_sa.inboundAuthKey().data(), AES_KEY_SIZE);
            
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

int main() {
    if (geteuid() != 0) {
        std::cerr << "This program requires root privileges for TUN interface and raw sockets" << std::endl;
        return 1;
    }
    
    OpenSSL_add_all_algorithms();
    
    std::cout << "ESP VPN Tunnel with Enhanced SA Management" << std::endl;
    std::cout << "Choose mode: (s)erver or (c)lient? ";
    
    char mode;
    std::cin >> mode;
    
    std::unique_ptr<ESPVPNTunnel> vpn;
    
    if (mode == 's' || mode == 'S') {
        vpn = std::make_unique<ESPVPNServer>();
        std::cout << "Starting ESP VPN Server..." << std::endl;
        
        // Server listens on all interfaces, port 4500
        if (!vpn->initialize("0.0.0.0", 4500)) {
            std::cerr << "Failed to initialize VPN server" << std::endl;
            return 1;
        }
        
        std::cout << "Enter client IP address: ";
        std::string client_ip;
        std::cin >> client_ip;
        
        // Create outbound SA to client (server -> client)
        vpn->createSA("0.0.0.0", 4500, client_ip, 8081, true);
        
        // Create inbound SA from client (client -> server)
        vpn->createSA("0.0.0.0", 4500, client_ip, 8081, false);
        
        vpn->start();
        
        std::cout << "\nServer running. Tunnel IP: 10.0.0.1" << std::endl;
        std::cout << "Clients can access LAN hosts via 192.168.50.x" << std::endl;
        std::cout << "Press Enter to show statistics, 'q' + Enter to quit..." << std::endl;
        
        std::string input;
        while (std::getline(std::cin, input)) {
            if (input == "q" || input == "quit") {
                break;
            } else if (input == "stats") {
                vpn->printStatistics();
            } else if (input == "sa") {
                vpn->printSAInfo();
            } else if (input.empty()) {
                vpn->printStatistics();
                vpn->printSAInfo();
            }
            std::cout << "\nPress Enter for stats, 'q' to quit: ";
        }
        
    } else {
        auto client = std::make_unique<ESPVPNClient>();
        vpn = std::move(client);
        
        std::cout << "Starting ESP VPN Client..." << std::endl;
        
        std::string server_ip;
        std::cout << "Enter server IP: ";
        std::cin >> server_ip;
        
        // Client binds to local IP, port 8081
        if (!vpn->initialize("0.0.0.0", 8081)) {
            std::cerr << "Failed to initialize VPN client" << std::endl;
            return 1;
        }
        
        // Create outbound SA to server (client -> server)
        vpn->createSA("0.0.0.0", 8081, server_ip, 4500, true);
        
        // Create inbound SA from server (server -> client)
        vpn->createSA("0.0.0.0", 8081, server_ip, 4500, false);
        
        vpn->start();
        
        std::cout << "\nClient connected. Tunnel IP: 10.0.0.2" << std::endl;
        std::cout << "You can now access LAN hosts at 192.168.50.x" << std::endl;
        
        ESPVPNClient* client_ptr = static_cast<ESPVPNClient*>(vpn.get());
        
        std::cout << "\nEntering interactive mode..." << std::endl;
        client_ptr->interactiveMode();
    }
    
    vpn->printStatistics();
    vpn->printSAInfo();
    vpn->stop();
    
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    
    return 0;
}