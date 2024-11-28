#pragma once

#include <cstdint>
#include <inaddr.h>

namespace ldpi
{
    enum class IPProtocol
    {
        ICMP = 1,
        TCP = 6,
        UDP = 17
    };

    struct IPHeader
    {
        uint8_t header_len:4,
                version:4;
        uint8_t tos;
        uint16_t length;
        uint16_t id;
        uint16_t offset;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t checksum;
        in_addr source;
        in_addr destination;
    };
}