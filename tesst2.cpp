#include <iostream>
//g++ -std=c++17 -o ESPVPNTunnel ESPVPNTunnel.cpp -lssl -lcrypto -lpthread
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
            lan_network = "192.168.50.0/24";  // Target LAN network (server's second interface)
            std::cout << "Server mode: Will provide access to LAN " << lan_network << std::endl;
        }
        else{
            local_port = 8081;
            remote_port = 4500;
            tunnel_ip = "10.0.0.2";  // Client tunnel IP
            std::cout << "Client mode: Will access remote LAN via tunnel" << std::endl;
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
    bool createTunInterface(const std::string& tun_name = "tun0") {
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
            
            // Cấu hình NAT cho traffic từ tunnel đến LAN 192.168.50.0/24
            std::cout << "Configuring NAT for tunnel -> LAN forwarding..." << std::endl;
            
            // MASQUERADE traffic từ tunnel network đến target LAN
            cmd = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -d 192.168.50.0/24 -j MASQUERADE 2>/dev/null || true";
            system(cmd.c_str());
            
            // Allow forwarding từ tunnel đến target LAN
            cmd = "iptables -A FORWARD -s 10.0.0.0/24 -d 192.168.50.0/24 -j ACCEPT 2>/dev/null || true";
            system(cmd.c_str());
            
            // Allow forwarding từ target LAN về tunnel
            cmd = "iptables -A FORWARD -s 192.168.50.0/24 -d 10.0.0.0/24 -j ACCEPT 2>/dev/null || true";
            system(cmd.c_str());
            
            // Add route để forward traffic đến 192.168.50.0/24 qua interface có IP trong dải đó
            // Tự động detect interface có IP 192.168.50.x
            cmd = "ip route show | grep '192.168.50' | head -1";
            system("echo 'Current routes to 192.168.50.0/24:'");
            system(cmd.c_str());
            
            std::cout << "Server configured to forward tunnel traffic to 192.168.50.0/24" << std::endl;
            
        } else {
            cmd = "ip addr add " + tunnel_ip + "/24 dev " + tun_name;
            system(cmd.c_str());
            cmd = "ip link set " + tun_name + " up";
            system(cmd.c_str());
            
            // Add route để truy cập 192.168.50.0/24 qua tunnel
            std::cout << "Adding route to target LAN via tunnel..." << std::endl;
            cmd = "ip route add 192.168.50.0/24 via 10.0.0.1 dev " + tun_name + " 2>/dev/null || true";
            system(cmd.c_str());
            
            // Verify route được add
            std::cout << "Routes to 192.168.50.0/24:" << std::endl;
            system("ip route show | grep 192.168.50 || echo 'No routes found'");
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

    // Create ICMP ping packet
    std::vector<uint8_t> createICMPPing(const std::string& src_ip, const std::string& dst_ip, 
                                       uint16_t id = 1234, uint16_t seq = 1) {
        std::vector<uint8_t> packet;
        
        // IP Header
        IPHeader ip_hdr;
        memset(&ip_hdr, 0, sizeof(ip_hdr));
        ip_hdr.version_ihl = 0x45;  // IPv4, header length 20 bytes
        ip_hdr.tos = 0;
        ip_hdr.total_length = htons(sizeof(IPHeader) + sizeof(ICMPHeader));
        ip_hdr.id = htons(12345);
        ip_hdr.flags_fragment = htons(0x4000);  // Don't fragment
        ip_hdr.ttl = 64;
        ip_hdr.protocol = IPPROTO_ICMP;
        ip_hdr.checksum = 0;
        inet_pton(AF_INET, src_ip.c_str(), &ip_hdr.src_addr);
        inet_pton(AF_INET, dst_ip.c_str(), &ip_hdr.dst_addr);
        
        // Calculate IP checksum
        ip_hdr.checksum = calculateIPChecksum(&ip_hdr, sizeof(IPHeader));
        
        // ICMP Header
        ICMPHeader icmp_hdr;
        memset(&icmp_hdr, 0, sizeof(icmp_hdr));
        icmp_hdr.type = 8;  // Echo Request
        icmp_hdr.code = 0;
        icmp_hdr.id = htons(id);
        icmp_hdr.sequence = htons(seq);
        icmp_hdr.checksum = 0;
        
        // Calculate ICMP checksum
        icmp_hdr.checksum = calculateIPChecksum(&icmp_hdr, sizeof(ICMPHeader));
        
        // Build packet
        packet.insert(packet.end(), (uint8_t*)&ip_hdr, (uint8_t*)&ip_hdr + sizeof(IPHeader));
        packet.insert(packet.end(), (uint8_t*)&icmp_hdr, (uint8_t*)&icmp_hdr + sizeof(ICMPHeader));
        
        return packet;
    }

    // Create TCP SYN packet
    std::vector<uint8_t> createTCPSyn(const std::string& src_ip, const std::string& dst_ip,
                                     uint16_t src_port, uint16_t dst_port) {
        std::vector<uint8_t> packet;
        
        // IP Header
        IPHeader ip_hdr;
        memset(&ip_hdr, 0, sizeof(ip_hdr));
        ip_hdr.version_ihl = 0x45;
        ip_hdr.tos = 0;
        ip_hdr.total_length = htons(sizeof(IPHeader) + sizeof(TCPHeader));
        ip_hdr.id = htons(54321);
        ip_hdr.flags_fragment = htons(0x4000);
        ip_hdr.ttl = 64;
        ip_hdr.protocol = IPPROTO_TCP;
        ip_hdr.checksum = 0;
        inet_pton(AF_INET, src_ip.c_str(), &ip_hdr.src_addr);
        inet_pton(AF_INET, dst_ip.c_str(), &ip_hdr.dst_addr);
        
        ip_hdr.checksum = calculateIPChecksum(&ip_hdr, sizeof(IPHeader));
        
        // TCP Header
        TCPHeader tcp_hdr;
        memset(&tcp_hdr, 0, sizeof(tcp_hdr));
        tcp_hdr.src_port = htons(src_port);
        tcp_hdr.dst_port = htons(dst_port);
        tcp_hdr.seq_num = htonl(1000);
        tcp_hdr.ack_num = 0;
        tcp_hdr.hdr_len_flags = htons(0x5002);  // Header length 20 bytes, SYN flag
        tcp_hdr.window_size = htons(65535);
        tcp_hdr.checksum = 0;
        tcp_hdr.urgent_ptr = 0;
        
        // TCP checksum calculation would go here (simplified for demo)
        
        // Build packet
        packet.insert(packet.end(), (uint8_t*)&ip_hdr, (uint8_t*)&ip_hdr + sizeof(IPHeader));
        packet.insert(packet.end(), (uint8_t*)&tcp_hdr, (uint8_t*)&tcp_hdr + sizeof(TCPHeader));
        
        return packet;
    }

    // Initialize the VPN tunnel
    bool initialize(const std::string& local_addr, const std::string& remote_addr) {
        local_ip = local_addr;
        remote_ip = remote_addr;
        
        std::cout << "Initializing ESP VPN Tunnel..." << std::endl;
        std::cout << "Local IP: " << local_ip << ":" << local_port << std::endl;
        if (!remote_ip.empty()) {
            std::cout << "Remote IP: " << remote_ip << ":" << remote_port << std::endl;
        }
        
        // Create TUN interface
        if (!createTunInterface()) {
            std::cerr << "Failed to create TUN interface" << std::endl;
            return false;
        }
        
        // Create raw socket for ESP packets
        raw_socket = socket(AF_INET, SOCK_RAW, ESP_PROTOCOL);
        if (raw_socket < 0) {
            std::cerr << "Failed to create raw socket for ESP (需要root权限)" << std::endl;
            return false;
        }
        
        // Create UDP socket for NAT-T
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket < 0) {
            std::cerr << "Failed to create UDP socket" << std::endl;
            return false;
        }
        
        // Set socket reuse options
        int reuse = 1;
        if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            std::cerr << "Warning: Failed to set SO_REUSEADDR" << std::endl;
        }
        
        // Bind UDP socket
        struct sockaddr_in local_addr_struct;
        memset(&local_addr_struct, 0, sizeof(local_addr_struct));
        local_addr_struct.sin_family = AF_INET;
        
        if (local_ip == "0.0.0.0" || local_ip.empty()) {
            local_addr_struct.sin_addr.s_addr = INADDR_ANY;
        } else {
            local_addr_struct.sin_addr.s_addr = inet_addr(local_ip.c_str());
        }
        local_addr_struct.sin_port = htons(local_port);
        
        if (bind(udp_socket, (struct sockaddr*)&local_addr_struct, sizeof(local_addr_struct)) < 0) {
            std::cerr << "Failed to bind UDP socket to port " << local_port << std::endl;
            perror("bind");
            return false;
        }
        
        std::cout << "ESP VPN Tunnel initialized successfully" << std::endl;
        
        if (is_server) {
            std::cout << "Server listening on port " << local_port << std::endl;
            std::cout << "Ready to provide access to LAN: " << lan_network << std::endl;
        } else {
            std::cout << "Client configured to connect to " << remote_ip << ":" << remote_port << std::endl;
            std::cout << "Will access target LAN: 192.168.50.0/24" << std::endl;
        }
        
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
        receive_thread = std::thread(&ESPVPNTunnel::receiveLoop, this);
        tun_thread = std::thread(&ESPVPNTunnel::tunReadLoop, this);
        
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

    // Send packet to LAN target
    bool sendPacketToLAN(const std::string& dst_ip, uint16_t dst_port, 
                        const std::string& packet_type = "ping") {
        uint32_t spi = 0;
        {
            std::lock_guard<std::mutex> lock(sa_mutex);
            if (!outbound_sas.empty()) {
                spi = outbound_sas.begin()->first;
            }
        }
        
        if (spi == 0) {
            std::cerr << "No outbound SA available" << std::endl;
            return false;
        }
        
        std::vector<uint8_t> ip_packet;
        
        if (packet_type == "ping") {
            ip_packet = createICMPPing(tunnel_ip, dst_ip);
        } else if (packet_type == "tcp") {
            ip_packet = createTCPSyn(tunnel_ip, dst_ip, 12345, dst_port);
        } else {
            std::cerr << "Unknown packet type: " << packet_type << std::endl;
            return false;
        }
        
        if (ip_packet.empty()) {
            std::cerr << "Failed to create IP packet" << std::endl;
            return false;
        }
        
        auto esp_packet = encapsulateESP(ip_packet, spi, IPPROTO_IP);
        if (esp_packet.empty()) {
            std::cerr << "Failed to encapsulate ESP packet" << std::endl;
            return false;
        }
        
        bool success = sendESPPacket(esp_packet);
        if (success) {
            std::cout << "Sent " << packet_type << " packet to " << dst_ip;
            if (packet_type == "tcp") {
                std::cout << ":" << dst_port;
            }
            std::cout << std::endl;
        }
        
        return success;
    }

    // Send test packet
    bool sendTestPacket(uint32_t spi, const std::string& test_data) {
        std::vector<uint8_t> payload(test_data.begin(), test_data.end());
        auto esp_packet = encapsulateESP(payload, spi, IPPROTO_TCP);
        
        if (esp_packet.empty()) {
            std::cerr << "Failed to encapsulate test packet" << std::endl;
            return false;
        }
        
        return sendESPPacket(esp_packet);
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

    // Test LAN connectivity
    void testLANConnectivity(const std::string& target_ip) {
        std::cout << "\n=== Testing LAN Connectivity to " << target_ip << " ===" << std::endl;
        
        // Send ICMP ping
        std::cout << "Sending ICMP ping..." << std::endl;
        sendPacketToLAN(target_ip, 0, "ping");
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Send TCP SYN to common ports
        std::vector<uint16_t> common_ports = {22, 23, 80, 443, 21, 25, 53, 110, 143, 993, 995};
        
        for (uint16_t port : common_ports) {
            std::cout << "Testing TCP port " << port << "..." << std::endl;
            sendPacketToLAN(target_ip, port, "tcp");
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    // Interactive mode for sending custom packets
    void interactiveMode() {
        std::string command;
        std::cout << "\n=== Interactive Mode ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  ping <ip>          - Send ICMP ping to IP" << std::endl;
        std::cout << "  tcp <ip> <port>    - Send TCP SYN to IP:port" << std::endl;
        std::cout << "  scan <ip>          - Port scan IP" << std::endl;
        std::cout << "  stats              - Show statistics" << std::endl;
        std::cout << "  quit               - Exit interactive mode" << std::endl;
        
        while (std::cin >> command && command != "quit") {
            if (command == "ping") {
                std::string ip;
                std::cin >> ip;
                sendPacketToLAN(ip, 0, "ping");
                
            } else if (command == "tcp") {
                std::string ip;
                uint16_t port;
                std::cin >> ip >> port;
                sendPacketToLAN(ip, port, "tcp");
                
            } else if (command == "scan") {
                std::string ip;
                std::cin >> ip;
                testLANConnectivity(ip);
                
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
        std::cerr << "Please run: sudo ./ESPVPNTunnel" << std::endl;
        return 1;
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    std::cout << "=== ESP VPN Tunnel with LAN Access ===" << std::endl;
    std::cout << "Network Topology:" << std::endl;
    std::cout << "  Client ←→ Server (via 192.168.2.0/24)" << std::endl;
    std::cout << "  Server ←→ Target LAN (192.168.50.0/24)" << std::endl;
    std::cout << "==========================================" << std::endl;
    
    std::cout << "Choose mode: (s)erver or (c)lient? ";
    
    char mode;
    std::cin >> mode;
    
    std::unique_ptr<ESPVPNTunnel> vpn;
    
    if (mode == 's' || mode == 'S') {
        vpn = std::make_unique<ESPVPNServer>();
        std::cout << "\n=== Starting ESP VPN Server ===" << std::endl;
        
        std::string server_listen_ip;
        std::cout << "Enter server listen IP in 192.168.2.0/24 network (or press Enter for 0.0.0.0): ";
        std::cin.ignore();
        std::getline(std::cin, server_listen_ip);
        if (server_listen_ip.empty()) {
            server_listen_ip = "0.0.0.0";
        }
        
        std::cout << "Server will provide access to LAN: 192.168.50.0/24" << std::endl;
        std::cout << "Make sure server has interface in both networks:" << std::endl;
        std::cout << "  - 192.168.2.x (for client connection)" << std::endl;
        std::cout << "  - 192.168.50.x (for target LAN access)" << std::endl;
        
        // Display current network interfaces
        std::cout << "\nCurrent network interfaces:" << std::endl;
        system("ip addr show | grep -E 'inet 192.168.(2|50)' | awk '{print $2, $NF}'");
        
        if (!vpn->initialize(server_listen_ip, "")) {
            std::cerr << "Failed to initialize VPN server" << std::endl;
            return 1;
        }
        
        // Create SAs for testing
        uint32_t out_spi = vpn->createSA_V2(true);
        uint32_t in_spi = vpn->createSA_V2(false);
        
        vpn->start();
        
        std::cout << "\n=== Server Status ===" << std::endl;
        std::cout << "✓ Server running on port 4500" << std::endl;
        std::cout << "✓ Tunnel IP: 10.0.0.1" << std::endl;
        std::cout << "✓ Ready to forward to 192.168.50.0/24" << std::endl;
        std::cout << "✓ Clients will get tunnel IP: 10.0.0.2" << std::endl;
        std::cout << "\nPress Enter to stop server..." << std::endl;
        std::cin.get();
        
    } else {
        auto client = std::make_unique<ESPVPNClient>();
        vpn = std::move(client);
        
        std::cout << "\n=== Starting ESP VPN Client ===" << std::endl;
        
        std::string server_ip;
        std::cout << "Enter server IP (192.168.2.x): ";
        std::cin >> server_ip;
        
        // Validate server IP is in expected range
        if (server_ip.substr(0, 11) != "192.168.2.") {
            std::cout << "Warning: Server IP should be in 192.168.2.0/24 network" << std::endl;
        }
        
        std::cout << "Connecting to server at " << server_ip << ":4500..." << std::endl;
        
        if (!vpn->initialize("0.0.0.0", server_ip)) {
            std::cerr << "Failed to initialize VPN client" << std::endl;
            return 1;
        }
        
        // Create SAs for testing
        uint32_t out_spi = vpn->createSA_V2(true);
        uint32_t in_spi = vpn->createSA_V2(false);
        
        vpn->start();
        
        std::cout << "\n=== Client Status ===" << std::endl;
        std::cout << "✓ Connected to server: " << server_ip << std::endl;
        std::cout << "✓ Tunnel IP: 10.0.0.2" << std::endl;
        std::cout << "✓ Route to 192.168.50.0/24 via tunnel" << std::endl;
        
        // Wait for connection to establish
        std::cout << "Waiting for connection to establish..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Test LAN connectivity
        std::string test_targets[] = {"192.168.50.1", "192.168.50.2", "192.168.50.254"};
        
        std::cout << "\n=== Testing LAN Connectivity ===" << std::endl;
        ESPVPNClient* client_ptr = static_cast<ESPVPNClient*>(vpn.get());
        
        for (const auto& target : test_targets) {
            std::cout << "\n--- Testing " << target << " ---" << std::endl;
            client_ptr->sendPacketToLAN(target, 0, "ping");
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
        
        // Focus on 192.168.50.2 as requested
        std::cout << "\n=== Detailed Test for 192.168.50.2 ===" << std::endl;
        client_ptr->testLANConnectivity("192.168.50.2");
        
        // Enter interactive mode
        std::cout << "\n=== Interactive Mode ===" << std::endl;
        std::cout << "You can now manually test connectivity to 192.168.50.x hosts" << std::endl;
        client_ptr->interactiveMode();
    }
    
    std::cout << "\n=== Final Statistics ===" << std::endl;
    vpn->printStatistics();
    vpn->printSAInfo();
    vpn->stop();
    
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    
    return 0;
}