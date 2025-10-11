#include <iostream>
//g++ -std=c++17 -O2 -o ESPfull ESPfull.cpp -lssl -lcrypto -lpthread
//scp /home/chien/vpn/ESPfull chien@172.31.213.48:/home/chien/
//scp /home/chien/vpn/ESPfull chien@192.168.2.24:/home/chien/
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


#ifndef ESP_VPN_FULL_H
#define ESP_VPN_FULL_H

#include <iostream>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <mutex>
#include <random>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <unistd.h>

// ESP Protocol Constants
#define ESP_PROTOCOL 50
#define UDP_ESP_PORT 4500
#define MAX_PACKET_SIZE 10000
#define ESP_HEADER_SIZE 8
#define ESP_TRAILER_MIN_SIZE 2
#define ESP_AUTH_SIZE 16
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define HMAC_KEY_SIZE 32

// ============================================================================
// TRAFFIC SELECTOR - Định nghĩa traffic nào được bảo vệ
// ============================================================================
struct TrafficSelector {
    uint32_t src_addr;      // Network byte order
    uint32_t src_mask;
    uint32_t dst_addr;
    uint32_t dst_mask;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    uint8_t protocol;       // 0 = any, IPPROTO_TCP, IPPROTO_UDP, etc.
    
    TrafficSelector() :
        src_addr(0), src_mask(0),
        dst_addr(0), dst_mask(0),
        src_port_start(0), src_port_end(65535),
        dst_port_start(0), dst_port_end(65535),
        protocol(0) {}
    
    // Parse CIDR notation
    static TrafficSelector fromCIDR(const std::string& src_cidr, 
                                    const std::string& dst_cidr,
                                    uint8_t proto = 0) {
        TrafficSelector ts;
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
    TrafficSelector selector;       // Traffic selector
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
    TrafficSelector selector;       // Traffic covered by this SA
    
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
    std::vector<TrafficSelector> allowed_selectors;
    
    PADEntry() : id(0), auth_method(AUTH_NULL) {}
    
    // Check if peer is authorized for this traffic
    bool authorizeTraffic(const TrafficSelector& ts) const {
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
    
    uint32_t addEntry(const TrafficSelector& ts, SPDAction action, 
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
    SADEntry* lookupOutbound(uint32_t dst_ip, const TrafficSelector& ts) {
        std::lock_guard<std::mutex> lock(mutex);
        
        for (auto& pair : entries) {
            SADEntry& sa = pair.second;
            
            // Check destination and state
            if (sa.dst_addr == dst_ip && sa.state == SA_STATE_MATURE) {
                // Check if traffic matches SA selector
                // In production: do proper selector matching
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
                                  const TrafficSelector& requested_ts) {
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

#endif // ESP_VPN_FULL_H

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
                            bool is_initiator) {
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
        TrafficSelector allowed_ts = TrafficSelector::fromCIDR("0.0.0.0/0", "0.0.0.0/0");
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
        
        outbound_sa.selector = TrafficSelector::fromCIDR("10.0.0.0/24", "192.168.50.0/24");
        
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
        
        inbound_sa.selector = TrafficSelector::fromCIDR("192.168.50.0/24", "10.0.0.0/24");
        
        sad.addEntry(inbound_sa);
        std::cout << "[SAD] Added INBOUND SA: SPI=0x" << std::hex << my_inbound_spi << std::dec << std::endl;
        
        // ========================================================================
        // 6. Create SPD entries
        // ========================================================================
        TrafficSelector ts_to_lan = TrafficSelector::fromCIDR("10.0.0.0/24", "192.168.50.0/24");
        TrafficSelector ts_from_lan = TrafficSelector::fromCIDR("192.168.50.0/24", "10.0.0.0/24");
        

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
        

            
            // TODO: Extract ports from TCP/UDP headers if needed
            
            // SPD lookup
            std::lock_guard<std::mutex> lock(database_mutex);
            SPDEntry* policy = spd.lookupOutbound(src_ip, dst_ip, src_port, dst_port, protocol);
            
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
            SADEntry* sa = sad.lookup(policy->sa_bundle_id); // cai nay phai la 0x2222222 nhung ma the deo nao no lai ra 0x11111
            std::cout << "[SAD] SA found for encrypt SPI: 0x" << std::hex 
                         << policy->sa_bundle_id << std::dec << std::endl;
                         
            if (!sa) {
                std::cerr << "[SAD] No SA found for SPI: 0x" << std::hex 
                         << policy->sa_bundle_id << std::dec << std::endl;
                packets_dropped++;
                continue;
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
            uint8_t next_header;
            auto decrypted_payload = decapsulateESP(esp_packet, next_header);
            
            if (!decrypted_payload.empty()) {
                processDecryptedPacket(decrypted_payload, next_header);
            }
        }
    }

    virtual void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) {
        if (next_header == IPPROTO_IP && payload.size() >= sizeof(IPHeader)) {
            const IPHeader* ip_header = reinterpret_cast<const IPHeader*>(payload.data());
            
            // Extract 5-tuple for inbound SPD check
            uint32_t src_ip = ip_header->src_addr;
            uint32_t dst_ip = ip_header->dst_addr;
            uint8_t protocol = ip_header->protocol;
            uint16_t src_port = 0, dst_port = 0;
            
            // Get SPI from the packet (we need to track this during decapsulation)
            uint32_t spi = 0; // Should be passed from decapsulateESP
            
            // Inbound SPD check
            std::lock_guard<std::mutex> lock(database_mutex);
            //std::cerr << "Decrypted packet! SPI: 0x" << std::hex << sa->spi << std::endl;

            SPDEntry* policy = spd.lookupInbound(src_ip, dst_ip, src_port, dst_port, protocol, spi);
            
            if (!policy) {
                std::cout << "[SPD] Inbound: No policy found, dropping packet" << std::endl;
                packets_dropped++;
                return;
            }
            
            policy->updateStats(payload.size());
            
            char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_header->src_addr, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_header->dst_addr, dst_ip_str, INET_ADDRSTRLEN);
            
            std::cout << "[INBOUND] " << src_ip_str << " -> " << dst_ip_str 
                     << " (Protocol: " << static_cast<int>(protocol) << ")" << std::endl;
            
            writeToTun(payload);
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
    
    void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) override {
        std::cout << "[CLIENT] Received " << payload.size() << " bytes" << std::endl;
        ESPVPNTunnel::processDecryptedPacket(payload, next_header);
    }

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
    
    void processDecryptedPacket(const std::vector<uint8_t>& payload, uint8_t next_header) override {
        std::cout << "[SERVER] Received " << payload.size() << " bytes" << std::endl;
        ESPVPNTunnel::processDecryptedPacket(payload, next_header);
    }
};

int main() {
    if (geteuid() != 0) {
        std::cerr << "This program requires root privileges" << std::endl;
        return 1;
    }
    
    OpenSSL_add_all_algorithms();
    
    std::cout << "ESP VPN Tunnel with RFC 4301 SPD/SAD/PAD Implementation" << std::endl;
    std::cout << "Choose mode: (s)erver or (c)lient? ";
    
    char mode;
    std::cin >> mode;
    
    std::unique_ptr<ESPVPNTunnel> vpn;
    
    if (mode == 's' || mode == 'S') {
        vpn = std::make_unique<ESPVPNServer>();
        std::cout << "Starting ESP VPN Server..." << std::endl;
        
        if (!vpn->initialize("0.0.0.0", 4500)) {
            std::cerr << "Failed to initialize VPN server" << std::endl;
            return 1;
        }
        
        std::cout << "Enter client IP address: ";
        std::string client_ip="172.31.213.48";
        // std::cin >> client_ip;
        client_ip="192.168.2.24";
        // Setup security policy
        if (!vpn->setupSecurityPolicy("0.0.0.0", 4500, client_ip, 8081, false)) {
            std::cerr << "Failed to setup security policy" << std::endl;
            return 1;
        }
        
        vpn->start();
        
        std::cout << "\nServer running. Tunnel IP: 10.0.0.1" << std::endl;
        std::cout << "Clients can access LAN hosts via 192.168.50.x" << std::endl;
        std::cout << "\nCommands:" << std::endl;
        std::cout << "  stats      - Show statistics" << std::endl;
        std::cout << "  databases  - Show SPD/SAD/PAD" << std::endl;
        std::cout << "  cleanup    - Cleanup expired SAs" << std::endl;
        std::cout << "  quit       - Exit" << std::endl;
        std::cout << "\nPress Enter for menu: ";
        
        std::string input;
        std::cin.ignore();
        while (std::getline(std::cin, input)) {
            if (input == "q" || input == "quit") {
                break;
            } else if (input == "stats") {
                vpn->printStatistics();
            } else if (input == "databases") {
                vpn->printDatabases();
            } else if (input == "cleanup") {
                vpn->cleanupExpiredSAs();
                std::cout << "Expired SAs cleaned up" << std::endl;
            } else if (input.empty()) {
                vpn->printStatistics();
            }
            std::cout << "\nPress Enter for menu: ";
        }
        
    } else {
        auto client = std::make_unique<ESPVPNClient>();
        
        std::cout << "Starting ESP VPN Client..." << std::endl;
        
        std::string server_ip="172.31.213.79";
        // std::cout << "Enter server IP: ";
        // std::cin >> server_ip;
        server_ip="192.168.2.25";
        
        if (!client->initialize("0.0.0.0", 8081)) {
            std::cerr << "Failed to initialize VPN client" << std::endl;
            return 1;
        }
        
        // Setup security policy
        if (!client->setupSecurityPolicy("0.0.0.0", 8081, server_ip, 4500, true)) {
            std::cerr << "Failed to setup security policy" << std::endl;
            return 1;
        }
        
        client->start();
        
        std::cout << "\nClient connected. Tunnel IP: 10.0.0.2" << std::endl;
        std::cout << "You can now access LAN hosts at 192.168.50.x" << std::endl;
        
        std::cout << "\nEntering interactive mode..." << std::endl;
        client->interactiveMode();
        
        vpn = std::move(client);
    }
    
    vpn->printStatistics();
    vpn->printDatabases();
    vpn->stop();
    
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    
    return 0;
}