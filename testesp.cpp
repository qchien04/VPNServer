#include <iostream>
//g++ -std=c++17 -o testesp testesp.cpp -lssl -lcrypto -lpthread
//sudo ./esp_vpn
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <mutex>
#include <random>
#include <cstring>
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

// ESP Protocol Constants
#define ESP_PROTOCOL 50
#define UDP_ESP_PORT 4500  // NAT-T port
#define MAX_PACKET_SIZE 1500
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
    // Encrypted payload follows
    // Authentication data at the end
} __attribute__((packed));

struct ESPTrailer {
    uint8_t padding_length;
    uint8_t next_header;
    // Authentication data follows
} __attribute__((packed));

// Security Association (SA) Structure
struct SecurityAssociation {
    uint32_t spi;
    uint8_t encryption_key[AES_KEY_SIZE];
    uint8_t authentication_key[HMAC_KEY_SIZE];
    std::string encryption_algo;
    std::string auth_algo;
    uint32_t sequence_number;
    
    SecurityAssociation() : spi(0), sequence_number(0) {
        encryption_algo = "AES-256-CBC";
        auth_algo = "HMAC-SHA256-128";
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

// TCP Header
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t hdr_len_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

// ICMP Header
struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} __attribute__((packed));

class ESPVPNTunnel {
protected:
    std::map<uint32_t, std::shared_ptr<SecurityAssociation>> outbound_sas;
    std::map<uint32_t, std::shared_ptr<SecurityAssociation>> inbound_sas;
    std::mutex sa_mutex;
    
    int raw_socket;
    int udp_socket;
    int tun_fd;  // TUN interface file descriptor
    bool is_server;
    std::string local_ip;
    std::string remote_ip;
    std::string tunnel_ip;  // IP của TUN interface
    std::string lan_network; // LAN network của server
    uint16_t local_port;
    uint16_t remote_port;
    
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
        local_port(UDP_ESP_PORT),
        remote_port(8081),
        running(false),
        packets_sent(0),
        packets_received(0),
        packets_encrypted(0),
        packets_decrypted(0),
        packets_dropped(0),
        tun_fd(-1) {
        
        if(is_server){
            local_port = 4500;
            remote_port = 8081;
            tunnel_ip = "10.0.0.1";  // Server tunnel IP
            lan_network = "192.168.50.0/24";  // LAN network
        }
        else{
            local_port = 8081;
            remote_port = 4500;
            tunnel_ip = "10.0.0.2";  // Client tunnel IP
        }
        raw_socket = -1;
        udp_socket = -1;
    }

    ~ESPVPNTunnel() {
        stop();
        if (raw_socket >= 0) close(raw_socket);
        if (udp_socket >= 0) close(udp_socket);
        if (tun_fd >= 0) close(tun_fd);
    }

    // Create TUN interface
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
        
        // Configure TUN interface
        std::string cmd;
        if (is_server) {
            cmd = "ip addr add " + tunnel_ip + "/24 dev " + tun_name;
            system(cmd.c_str());
            cmd = "ip link set " + tun_name + " up";
            system(cmd.c_str());
            
            // Enable IP forwarding
            system("echo 1 > /proc/sys/net/ipv4/ip_forward");
            
            // Add iptables rules for NAT to LAN
            cmd = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 192.168.50.0/24 -j MASQUERADE";
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
            
            // Add route to LAN through tunnel
            cmd = "ip route add 192.168.50.0/24 via 10.0.0.1 dev " + tun_name;
            system(cmd.c_str());
        }
        
        return true;
    }

    // Calculate IP checksum
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

    // Initialize the VPN tunnel
    bool initialize(const std::string& local_addr, const std::string& remote_addr) {
        local_ip = local_addr;
        remote_ip = remote_addr;
        
        // Create TUN interface
        if (!createTunInterface()) {
            std::cerr << "Failed to create TUN interface" << std::endl;
            return false;
        }
        
        // Create raw socket for ESP packets
        raw_socket = socket(AF_INET, SOCK_RAW, ESP_PROTOCOL);
        if (raw_socket < 0) {
            std::cerr << "Failed to create raw socket for ESP" << std::endl;
            return false;
        }
        
        // Create UDP socket for NAT-T
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket < 0) {
            std::cerr << "Failed to create UDP socket" << std::endl;
            return false;
        }
        
        // Bind UDP socket
        struct sockaddr_in local_addr_struct;
        memset(&local_addr_struct, 0, sizeof(local_addr_struct));
        local_addr_struct.sin_family = AF_INET;
        local_addr_struct.sin_addr.s_addr = INADDR_ANY;
        local_addr_struct.sin_port = htons(local_port);
        
        if (bind(udp_socket, (struct sockaddr*)&local_addr_struct, sizeof(local_addr_struct)) < 0) {
            std::cerr << "Failed to bind UDP socket" << std::endl;
            return false;
        }
        
        std::cout << "ESP VPN Tunnel initialized successfully" << std::endl;
        return true;
    }

    uint32_t createSA_V2(bool outbound = true) {
        auto sa = std::make_shared<SecurityAssociation>();

        // Fixed SPI
        sa->spi = 0x11111111;  

        // Fixed AES-256 key (32 bytes)
        static const uint8_t fixed_key[AES_KEY_SIZE] = {
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
            0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
            0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
        };
        memcpy(sa->encryption_key, fixed_key, AES_KEY_SIZE);

        // Fixed HMAC key (32 bytes)
        static const uint8_t fixed_hmac[HMAC_KEY_SIZE] = {
            0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,
            0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
            0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,
            0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
        };
        memcpy(sa->authentication_key, fixed_hmac, HMAC_KEY_SIZE);

        // Store in SA table
        std::lock_guard<std::mutex> lock(sa_mutex);
        if (outbound) {
            outbound_sas[sa->spi] = sa;
        } else {
            inbound_sas[sa->spi] = sa;
        }

        std::cout << "Created SA with fixed SPI: 0x" 
                << std::hex << sa->spi << std::dec << std::endl;

        return sa->spi;
    }

    // AES-CBC encryption
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

    // AES-CBC decryption
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

    // HMAC-SHA256-128 authentication
    std::vector<uint8_t> calculateHMAC(const std::vector<uint8_t>& data, const uint8_t* key) {
        unsigned int hmac_len;
        uint8_t hmac_full[SHA256_DIGEST_LENGTH];

        HMAC(EVP_sha256(), key, HMAC_KEY_SIZE,
            data.data(), data.size(),
            hmac_full, &hmac_len);

        // Return first 128 bits (16 bytes) as per RFC 4868
        std::vector<uint8_t> hmac_128(hmac_full, hmac_full + ESP_AUTH_SIZE);
        return hmac_128;
    }

    // Verify HMAC
    bool verifyHMAC(const std::vector<uint8_t>& data, 
                   const std::vector<uint8_t>& received_hmac, 
                   const uint8_t* key) {
        auto calculated_hmac = calculateHMAC(data, key);
        return calculated_hmac == received_hmac;
    }

    // Apply padding for encryption
    std::vector<uint8_t> applyPadding(const std::vector<uint8_t>& data, uint8_t next_header) {
        // Calculate padding needed for AES block alignment
        size_t total_size = data.size() + sizeof(ESPTrailer);
        size_t padding_needed = AES_BLOCK_SIZE - (total_size % AES_BLOCK_SIZE);
        if (padding_needed == AES_BLOCK_SIZE) padding_needed = 0;
        
        std::vector<uint8_t> padded_data = data;
        
        // Add padding bytes (value = padding length - 1)
        for (size_t i = 0; i < padding_needed; i++) {
            padded_data.push_back(static_cast<uint8_t>(i + 1));
        }
        
        // Add ESP trailer
        ESPTrailer trailer;
        trailer.padding_length = static_cast<uint8_t>(padding_needed);
        trailer.next_header = next_header;
        
        padded_data.insert(padded_data.end(), 
                          reinterpret_cast<uint8_t*>(&trailer), 
                          reinterpret_cast<uint8_t*>(&trailer) + sizeof(ESPTrailer));
        
        return padded_data;
    }

    // Remove padding after decryption
    std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data, uint8_t& next_header) {
        if (data.size() < sizeof(ESPTrailer)) return {};
        
        // Extract ESP trailer
        size_t trailer_offset = data.size() - sizeof(ESPTrailer);
        const ESPTrailer* trailer = reinterpret_cast<const ESPTrailer*>(data.data() + trailer_offset);
        
        next_header = trailer->next_header;
        uint8_t padding_length = trailer->padding_length;
        
        // Verify padding
        if (padding_length >= data.size() - sizeof(ESPTrailer)) return {};
        
        // Return data without padding and trailer
        size_t payload_size = data.size() - sizeof(ESPTrailer) - padding_length;
        return std::vector<uint8_t>(data.begin(), data.begin() + payload_size);
    }

    // Encapsulate packet with ESP
    std::vector<uint8_t> encapsulateESP(const std::vector<uint8_t>& payload, 
                                       uint32_t spi, 
                                       uint8_t next_header = IPPROTO_IP) {
        std::lock_guard<std::mutex> lock(sa_mutex);
        
        auto sa_it = outbound_sas.find(spi);
        if (sa_it == outbound_sas.end()) {
            std::cerr << "Invalid or inactive outbound SA: " << spi << std::endl;
            return {};
        }
        
        auto sa = sa_it->second;
        sa->sequence_number++;
        
        // Create ESP header
        ESPHeader esp_header;
        esp_header.spi = htonl(sa->spi);
        esp_header.sequence = htonl(sa->sequence_number);
        
        // Apply padding
        auto padded_payload = applyPadding(payload, next_header);
        
        // Generate random IV
        uint8_t iv[AES_BLOCK_SIZE];
        if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
            std::cerr << "Failed to generate IV" << std::endl;
            return {};
        }
        
        // Encrypt payload
        auto encrypted_payload = encryptAES(padded_payload, sa->encryption_key, iv);
        if (encrypted_payload.empty()) {
            std::cerr << "Encryption failed" << std::endl;
            return {};
        }
        
        // Build ESP packet for authentication
        std::vector<uint8_t> esp_packet;
        esp_packet.insert(esp_packet.end(), 
                         reinterpret_cast<uint8_t*>(&esp_header),
                         reinterpret_cast<uint8_t*>(&esp_header) + sizeof(ESPHeader));
        esp_packet.insert(esp_packet.end(), iv, iv + AES_BLOCK_SIZE);
        esp_packet.insert(esp_packet.end(), encrypted_payload.begin(), encrypted_payload.end());
        
        // Calculate HMAC
        auto hmac = calculateHMAC(esp_packet, sa->authentication_key);
        esp_packet.insert(esp_packet.end(), hmac.begin(), hmac.end());
        
        packets_encrypted++;
        
        return esp_packet;
    }

    // Decapsulate ESP packet
    std::vector<uint8_t> decapsulateESP(const std::vector<uint8_t>& esp_packet, uint8_t& next_header) {
        if (esp_packet.size() < sizeof(ESPHeader) + AES_BLOCK_SIZE + ESP_AUTH_SIZE) {
            packets_dropped++;
            return {};
        }
        
        // Extract ESP header
        const ESPHeader* esp_header = reinterpret_cast<const ESPHeader*>(esp_packet.data());
        uint32_t spi = ntohl(esp_header->spi);
        uint32_t sequence = ntohl(esp_header->sequence);
        
        std::lock_guard<std::mutex> lock(sa_mutex);
        
        auto sa_it = inbound_sas.find(spi);
        if (sa_it == inbound_sas.end()) {
            std::cerr << "Invalid or inactive inbound SA: " << spi << std::endl;
            packets_dropped++;
            return {};
        }
        
        auto sa = sa_it->second;
    
        
        // Verify HMAC
        size_t payload_size = esp_packet.size() - ESP_AUTH_SIZE;
        std::vector<uint8_t> packet_for_auth(esp_packet.begin(), esp_packet.begin() + payload_size);
        std::vector<uint8_t> received_hmac(esp_packet.end() - ESP_AUTH_SIZE, esp_packet.end());
        
        if (!verifyHMAC(packet_for_auth, received_hmac, sa->authentication_key)) {
            std::cerr << "HMAC verification failed" << std::endl;
            packets_dropped++;
            return {};
        }
        
        // Extract IV and encrypted payload
        const uint8_t* iv = esp_packet.data() + sizeof(ESPHeader);
        size_t encrypted_payload_size = payload_size - sizeof(ESPHeader) - AES_BLOCK_SIZE;
        std::vector<uint8_t> encrypted_payload(
            esp_packet.begin() + sizeof(ESPHeader) + AES_BLOCK_SIZE,
            esp_packet.begin() + sizeof(ESPHeader) + AES_BLOCK_SIZE + encrypted_payload_size
        );
        
        // Decrypt payload
        auto decrypted_payload = decryptAES(encrypted_payload, sa->encryption_key, iv);
        if (decrypted_payload.empty()) {
            std::cerr << "Decryption failed" << std::endl;
            packets_dropped++;
            return {};
        }
        
        // Remove padding
        auto original_payload = removePadding(decrypted_payload, next_header);
        if (original_payload.empty()) {
            std::cerr << "Padding removal failed" << std::endl;
            packets_dropped++;
            return {};
        }
        packets_decrypted++;
        
        return original_payload;
    }

    // Send ESP packet via UDP (NAT-T)
    bool sendESPPacket(const std::vector<uint8_t>& esp_packet) {
        struct sockaddr_in remote_addr;
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_addr.s_addr = inet_addr(remote_ip.c_str());
        remote_addr.sin_port = htons(remote_port);
        
        // Add NAT-T non-ESP marker (4 zero bytes)
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

    // Read packet from TUN interface and send through VPN
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
            
            // Encapsulate and send via ESP
            std::vector<uint8_t> ip_packet(buffer, buffer + packet_size);
            
            // Get the first available outbound SPI
            uint32_t spi = 0;
            {
                std::lock_guard<std::mutex> lock(sa_mutex);
                if (!outbound_sas.empty()) {
                    spi = outbound_sas.begin()->first;
                }
            }
            
            if (spi != 0) {
                auto esp_packet = encapsulateESP(ip_packet, spi, IPPROTO_IP);
                if (!esp_packet.empty()) {
                    sendESPPacket(esp_packet);
                    
                    // Parse and display packet info
                    if (packet_size >= sizeof(IPHeader)) {
                        const IPHeader* ip_hdr = reinterpret_cast<const IPHeader*>(buffer);
                        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &ip_hdr->src_addr, src_ip, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &ip_hdr->dst_addr, dst_ip, INET_ADDRSTRLEN);
                        
                        std::cout << "Forwarded packet: " << src_ip << " -> " << dst_ip 
                                << " (Protocol: " << static_cast<int>(ip_hdr->protocol) << ")" << std::endl;
                    }
                }
            }
        }
    }

    // Write decrypted packet to TUN interface
    void writeToTun(const std::vector<uint8_t>& packet) {
        if (tun_fd < 0) return;
        
        ssize_t written = write(tun_fd, packet.data(), packet.size());
        if (written < 0) {
            std::cerr << "Error writing to TUN interface" << std::endl;
        } else {
            std::cout << "Wrote " << written << " bytes to TUN interface" << std::endl;
        }
    }

    // Receive and process ESP packets
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
            
            // Check for NAT-T non-ESP marker
            if (received < 4 || memcmp(buffer, "\x00\x00\x00\x00", 4) != 0) {
                std::cerr << "Invalid NAT-T packet format" << std::endl;
                packets_dropped++;
                continue;
            }
            
            // Process ESP packet (skip NAT-T marker)
            std::vector<uint8_t> esp_packet(buffer + 4, buffer + received);
            uint8_t next_header;
            auto decrypted_payload = decapsulateESP(esp_packet, next_header);
            
            if (!decrypted_payload.empty()) {
                processDecryptedPacket(decrypted_payload, next_header);
            }
        }
    }

    // Process decrypted packet
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
            
            // Write to TUN interface for further processing
            writeToTun(payload);
        } else {
            // Display as text if possible
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

    // Start the VPN tunnel
    bool start() {
        if (running) return true;
        
        running = true;
        receive_thread = std::thread(&ESPVPNTunnel::receiveLoop, this); //receive and write tun
        tun_thread = std::thread(&ESPVPNTunnel::tunReadLoop, this); //encry and send packet
        
        std::cout << "ESP VPN Tunnel started" << std::endl;
        return true;
    }

    // Stop the VPN tunnel
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


    // Print statistics
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

    // Get SA information
    void printSAInfo() {
        std::lock_guard<std::mutex> lock(sa_mutex);
        
        std::cout << "\n=== Outbound Security Associations ===" << std::endl;
        for (const auto& pair : outbound_sas) {
            auto sa = pair.second;
            std::cout << "SPI: 0x" << std::hex << sa->spi << std::dec
                     << ", Seq: " << sa->sequence_number << std::endl;
        }
        
        std::cout << "\n=== Inbound Security Associations ===" << std::endl;
        for (const auto& pair : inbound_sas) {
            auto sa = pair.second;
            std::cout << "SPI: 0x" << std::hex << sa->spi << std::dec << std::endl;
        }
    }
};

// Client class with LAN access capabilities
class ESPVPNClient : public ESPVPNTunnel {
public:
    ESPVPNClient() : ESPVPNTunnel(false) {}
    
    void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) override {
        std::cout << "[CLIENT] Received " << payload.size() << " bytes" << std::endl;
        ESPVPNTunnel::processDecryptedPacket(payload, next_header);
    }

    // Interactive mode for sending custom packets
    void interactiveMode() {
        std::string command;
        std::cout << "\n=== Interactive Mode ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  stats              - Show statistics" << std::endl;
        std::cout << "  quit               - Exit interactive mode" << std::endl;
        
        while (std::cin >> command && command != "quit") {
            if (command == "ok") {
                std::string ip;
                std::cout<< "ok";                
            } else if (command == "stats") {
                printStatistics();
                
            } else {
                std::cout << "Unknown command: " << command << std::endl;
            }
            
            std::cout << "> ";
        }
    }
};

// Server class with LAN forwarding capabilities
class ESPVPNServer : public ESPVPNTunnel {
public:
    ESPVPNServer() : ESPVPNTunnel(true) {}
    
    void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) override {
        std::cout << "[SERVER] Received " << payload.size() << " bytes" << std::endl;
        ESPVPNTunnel::processDecryptedPacket(payload, next_header);
        
        // Server automatically forwards packets to TUN interface
        // The kernel will handle routing to LAN based on routing table
    }
};

// Main function for demonstration
int main() {
    // Check if running as root
    if (geteuid() != 0) {
        std::cerr << "This program requires root privileges for TUN interface and raw sockets" << std::endl;
        return 1;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    std::cout << "ESP VPN Tunnel with LAN Access Implementation" << std::endl;
    std::cout << "Choose mode: (s)erver or (c)lient? ";
    
    char mode;
    std::cin >> mode;
    
    std::unique_ptr<ESPVPNTunnel> vpn;
    
    if (mode == 's' || mode == 'S') {
        vpn = std::make_unique<ESPVPNServer>();
        std::cout << "Starting ESP VPN Server..." << std::endl;
        std::cout << "Server will provide access to LAN: 192.168.50.0/24" << std::endl;
        
        if (!vpn->initialize("0.0.0.0", "")) {
            std::cerr << "Failed to initialize VPN server" << std::endl;
            return 1;
        }
        
        // Create SAs for testing
        uint32_t out_spi = vpn->createSA_V2(true);
        uint32_t in_spi = vpn->createSA_V2(false);
        
        vpn->start();
        
        std::cout << "Server running. Tunnel IP: 10.0.0.1" << std::endl;
        std::cout << "Clients can access LAN hosts via 192.168.50.x" << std::endl;
        std::cout << "Press Enter to stop..." << std::endl;
        std::cin.ignore();
        std::cin.get();
        
    } else {
        auto client = std::make_unique<ESPVPNClient>();
        vpn = std::move(client);
        
        std::cout << "Starting ESP VPN Client..." << std::endl;
        
        std::string server_ip;
        std::cout << "Enter server IP: ";
        std::cin >> server_ip;
        
        if (!vpn->initialize("0.0.0.0", server_ip)) {
            std::cerr << "Failed to initialize VPN client" << std::endl;
            return 1;
        }
        
        // Create SAs for testing
        uint32_t out_spi = vpn->createSA_V2(true);
        uint32_t in_spi = vpn->createSA_V2(false);
        
        vpn->start();
        
        std::cout << "Client connected. Tunnel IP: 10.0.0.2" << std::endl;
        std::cout << "You can now access LAN hosts at 192.168.50.x" << std::endl;
        
        ESPVPNClient* client_ptr = static_cast<ESPVPNClient*>(vpn.get());
        
        // Enter interactive mode
        std::cout << "\nEntering interactive mode..." << std::endl;
        client_ptr->interactiveMode();
    }
    
    vpn->printStatistics();
    vpn->printSAInfo();
    vpn->stop();
    
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    
    return 0;
}