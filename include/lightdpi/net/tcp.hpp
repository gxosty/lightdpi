#pragma once

#include <cstdint>

namespace ldpi
{
    // namespace as scope
    namespace TCPFlags
    {
        static constexpr uint8_t FIN = 0x01;
        static constexpr uint8_t SYN = 0x02;
        static constexpr uint8_t RST = 0x04;
        static constexpr uint8_t PSH = 0x08;
        static constexpr uint8_t ACK = 0x10;
        static constexpr uint8_t URG = 0x20;
        static constexpr uint8_t ECE = 0x40;
        static constexpr uint8_t CWR = 0x80;
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