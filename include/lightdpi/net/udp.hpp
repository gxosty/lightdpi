#pragma once

#include <cstdint>

namespace ldpi
{
    struct UDPHeader
    {
        uint16_t source_port;
        uint16_t destination_port;
        uint16_t length;
        uint16_t checksum;
    };
}