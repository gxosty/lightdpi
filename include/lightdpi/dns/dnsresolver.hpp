#pragma once

#include "../common/packet.hpp"

namespace ldpi
{
    // Abstract class
    class DNSResolver
    {
    public:
        virtual ~DNSResolver() {}
        // Takes the whole DNS query packet and
        // returns DNS response packet
        virtual void resolve(Packet* in_packet, Packet* out_packet) = 0;
    };
}