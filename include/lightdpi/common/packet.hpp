#pragma once

#include "buffer.hpp"
#include "../net/ip.hpp"
#include "../net/tcp.hpp"
#include "../net/udp.hpp"

namespace ldpi
{
    class Packet : public Buffer
    {
    public:
        Packet() : Buffer() {};

        Packet* copy();

        IPHeader* get_ip_header() const;
        IPProtocol get_protocol() const;
        InBuffer get_body() const;

        template <class T>
        T* get_transport_layer() const
        {
            IPHeader* ip_header = this->get_ip_header();
            char* transport_layer = ((char*)&_buffer) + ip_header->header_len * 4;
            return reinterpret_cast<T*>(transport_layer);
        }
    };
}