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
        void print() const;

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

        // shortcuts
        bool is_tcp_syn();
        bool is_http_request();
        bool is_tls_client_hello();

        void update_checksums();
        void reverse_direction();
        void make_unique();
    };
}