#pragma once
#include "common.h"
#include <vector>

struct TrafficSelector {
    uint8_t ts_type;
    uint8_t ip_protocol_id;
    uint16_t selector_length;
    uint16_t start_port;
    uint16_t end_port;
    std::vector<uint8_t> starting_address;
    std::vector<uint8_t> ending_address;

    bool static ip_in_range(uint32_t ip, const std::vector<uint8_t>& start, const std::vector<uint8_t>& end) {
        uint32_t s = (start[0]<<24) | (start[1]<<16) | (start[2]<<8) | start[3];
        uint32_t e = (end[0]<<24) | (end[1]<<16) | (end[2]<<8) | end[3];
        return ip >= s && ip <= e;
    }
    bool matches(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) const {
        if (!ip_in_range(src_ip, starting_address, ending_address)) return false;
        if (!ip_in_range(dst_ip, starting_address, ending_address)) return false;

        if (ip_protocol_id != 0 && ip_protocol_id != proto) return false;

        if (src_port < start_port || src_port > end_port) return false;
        if (dst_port < start_port || dst_port > end_port) return false;

        return true;
    }

};
