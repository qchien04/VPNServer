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
};
