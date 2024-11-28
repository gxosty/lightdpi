#pragma once

#include <cstdint>

namespace ldpi
{
    enum class TCPFlags
    {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20,
        ECE = 0x40,
        CWR = 0x80,
    };

    struct TCPHeader
    {
        uint16_t source_port;
        uint16_t destination_port;
        uint32_t seq_number;
        uint32_t ack_number;
        uint8_t _reserved:4,
                offset:4;
        uint8_t flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_pointer;
    };
}