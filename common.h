#pragma once
#include <iostream>
#include <memory>
#include <arpa/inet.h>
// Utility macros for error checking
#define CHECK_OPENSSL(expr) \
    do { \
        if (!(expr)) { \
            unsigned long err = ERR_get_error(); \
            char buf[256]; \
            ERR_error_string_n(err, buf, sizeof(buf)); \
            throw std::runtime_error(std::string("OpenSSL error: ") + buf); \
        } \
    } while(0)

// IKEv2 Message Types
enum class IKEMessageType : uint8_t {
    IKE_SA_INIT = 34,
    IKE_AUTH = 35,
    CREATE_CHILD_SA = 36,
    INFORMATIONAL = 37
};

// IKEv2 Payload Types
enum class PayloadType : uint8_t {
    NO_NEXT_PAYLOAD = 0,
    SA = 33,
    KE = 34,
    IDi = 35,
    IDr = 36,
    CERT = 37,
    CERTREQ = 38,
    AUTH = 39,
    Ni = 40,
    Nr = 41,
    N = 41,
    D = 42,
    V = 43,
    TSi = 44,
    TSr = 45,
    SK = 46
};

// IKE Flags
enum IKEFlags : uint8_t {
    RESPONSE_FLAG = 0x20,
    VERSION_FLAG = 0x10,
    INITIATOR_FLAG = 0x08
};

// Transform Types
enum class TransformType : uint8_t {
    ENCR = 1,  // Encryption Algorithm
    PRF = 2,   // Pseudo-random Function
    INTEG = 3, // Integrity Algorithm
    DH = 4     // Diffie-Hellman Group
};

// Encryption Algorithms
enum class EncryptionAlgorithm : uint16_t {
    AES_CBC_128 = 12,
    AES_CBC_192 = 13,
    AES_CBC_256 = 14
};

// PRF Algorithms
enum class PRFAlgorithm : uint16_t {
    PRF_HMAC_SHA1 = 2,
    PRF_HMAC_SHA256 = 5
};

// Integrity Algorithms
enum class IntegrityAlgorithm : uint16_t {
    AUTH_HMAC_SHA1_96 = 2,
    AUTH_HMAC_SHA256_128 = 12
};

// DH Groups
enum class DHGroup : uint16_t {
    MODP_768 = 1,
    MODP_1024 = 2,
    MODP_1536 = 5,
    MODP_2048 = 14,
    MODP_3072 = 15,
    MODP_4096 = 16
};

// Protocol IDs
enum class ProtocolID : uint8_t {
    IKE = 1,
    AH = 2,
    ESP = 3
};

// Utility functions for network byte order
uint16_t host_to_net16(uint16_t value) {
    return htons(value);
}

uint32_t host_to_net32(uint32_t value) {
    return htonl(value);
}

uint16_t net_to_host16(uint16_t value) {
    return ntohs(value);
}

uint32_t net_to_host32(uint32_t value) {
    return ntohl(value);
}