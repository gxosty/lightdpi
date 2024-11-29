#pragma once

#include "ip.hpp"
#include "tcp.hpp"
#include "udp.hpp"

namespace ldpi
{
    uint16_t calculate_ip_checksum(IPHeader* ip_header);
    uint16_t calculate_tcp_checksum(IPHeader* ip_header, TCPHeader* tcp_header);
    uint16_t calculate_udp_checksum(IPHeader* ip_header, UDPHeader* udp_header);
}