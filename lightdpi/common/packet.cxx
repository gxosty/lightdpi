#include <lightdpi/common/packet.hpp>
#include <lightdpi/net/checksum.hpp>

#include "../internal/logger.hpp"

#include <cstdio>
#include <unordered_map>
#include <random>

#include <ws2tcpip.h>

namespace ldpi
{
    static internal::Logger logger;

    Packet* Packet::copy()
    {
        Packet* new_packet = new Packet();
        new_packet->copy_from(_data, _size);
        return new_packet;
    }

    IPHeader* Packet::get_ip_header() const
    {
        return (IPHeader*)_data;
    }

    IPProtocol Packet::get_protocol() const
    {
        return static_cast<IPProtocol>(((IPHeader*)_data)->protocol);
    }

    InBuffer Packet::get_body() const
    {
        IPProtocol protocol = this->get_protocol();

        char* data;

        switch (protocol)
        {
        case IPProtocol::TCP:
            {
                TCPHeader* tcp_header = this->get_transport_layer<TCPHeader>();
                data = ((char*)tcp_header) + tcp_header->offset * 4;
            }
            break;
        case IPProtocol::UDP:
            {
                UDPHeader* udp_header = this->get_transport_layer<UDPHeader>();
                data = (char*)(udp_header + 1);
            }
            break;
        default:
            return InBuffer(nullptr, 0);
        }

        size_t size
            = _size
            - (reinterpret_cast<uintptr_t>(data)
            - reinterpret_cast<uintptr_t>(_data));

        return InBuffer(data, size);
    }

    bool Packet::is_tcp_syn()
    {
        if (this->get_protocol() != IPProtocol::TCP)
        {
            return false;
        }

        TCPHeader* tcp_header = this->get_transport_layer<TCPHeader>();

        return bool(tcp_header->flags & TCPFlags::SYN);
    }

    bool Packet::is_http_request()
    {
        return false;
    }

    bool Packet::is_tls_client_hello()
    {
        if (this->get_protocol() != IPProtocol::TCP)
        {
            return false;
        }

        TCPHeader* tcp_header = this->get_transport_layer<TCPHeader>();

        namespace f = TCPFlags;
        if ((tcp_header->flags != f::ACK) && (tcp_header->flags != (f::PSH | f::ACK)))
        {
            return false;
        }

        InBuffer data = this->get_body();

        if (data.get_size() < 3)
        {
            return false;
        }

        return (
            (data[0] == 0x16) &&
            (data[1] == 0x03) &&
            (
                (data[2] == 0x01) ||
                (data[2] == 0x03)
            )
        );
    }

    void Packet::reverse_direction()
    {
        IPProtocol protocol = this->get_protocol();

        switch (protocol)
        {
        case IPProtocol::TCP:
            // TODO
            break;
        case IPProtocol::UDP:
            {
                IPHeader* ip_header = this->get_ip_header();
                UDPHeader* udp_header = this->get_transport_layer<UDPHeader>();

                in_addr sv_addr = ip_header->destination;
                uint16_t sv_port = udp_header->destination_port;
                ip_header->destination = ip_header->source;
                udp_header->destination_port = udp_header->source_port;
                ip_header->source = sv_addr;
                udp_header->source_port = sv_port;

                ip_header->checksum = calculate_ip_checksum(ip_header);
                udp_header->checksum = calculate_udp_checksum(ip_header, udp_header);
            }
            break;
        default:
            break;
        }
    }

    void Packet::print() const
    {
        printf("----------=[Packet Start]=----------\n");

        IPProtocol protocol = this->get_protocol();
        static std::unordered_map<uint8_t, char*> protocol_str = {
            {static_cast<uint8_t>(IPProtocol::ICMP), (char*)"ICMP"},
            {static_cast<uint8_t>(IPProtocol::TCP), (char*)"TCP"},
            {static_cast<uint8_t>(IPProtocol::UDP), (char*)"UDP"}
        };

        IPHeader* ip_header = this->get_ip_header();

        printf("[IP Header]\n");
        printf(" header_len = %u\n", (uint32_t)ip_header->header_len);
        printf(" version = %u\n", (uint32_t)ip_header->version);
        printf(" tos = %u\n", (uint32_t)ip_header->tos);
        printf(" length = %u\n", (uint32_t)ntohs(ip_header->length));
        printf(" id = %u\n", (uint32_t)ntohs(ip_header->id));
        printf(" offset = %u\n", (uint32_t)ntohs(ip_header->offset));
        printf(" ttl = %u\n", (uint32_t)ip_header->ttl);
        printf(" protocol = %u (%s)\n",
            (uint32_t)ip_header->protocol,
            protocol_str[(uint8_t)(ip_header->protocol)]
        );
        printf(" checksum = %u\n", (uint32_t)ntohs(ip_header->checksum));
        printf(" source = %s\n", inet_ntoa(ip_header->source));
        printf(" destination = %s\n", inet_ntoa(ip_header->destination));

        switch (protocol)
        {
        case IPProtocol::TCP:
            {
                printf("[TCP Header]\n");
                TCPHeader* tcp_header = this->get_transport_layer<TCPHeader>();
                uint8_t f = tcp_header->flags;
                printf(" source_port = %u\n", (uint32_t)ntohs(tcp_header->source_port));
                printf(" destination_port = %u\n", (uint32_t)ntohs(tcp_header->destination_port));
                printf(" seq_number = %lu\n", ntohl(tcp_header->seq_number));
                printf(" ack_number = %lu\n", ntohl(tcp_header->ack_number));
                printf(" _reserved = \\x00\\x00\n");
                printf(" offset = %u\n", (uint32_t)tcp_header->offset);
                printf(" flags = %s%s%s%s%s%s%s%s\n",
                    (f & TCPFlags::FIN ? "F" : ""),
                    (f & TCPFlags::SYN ? "S" : ""),
                    (f & TCPFlags::RST ? "R" : ""),
                    (f & TCPFlags::PSH ? "P" : ""),
                    (f & TCPFlags::ACK ? "A" : ""),
                    (f & TCPFlags::URG ? "U" : ""),
                    (f & TCPFlags::ECE ? "E" : ""),
                    (f & TCPFlags::CWR ? "C" : "")
                );
                printf(" window = %u\n", (uint32_t)ntohs(tcp_header->window));
                printf(" checksum = %u\n", (uint32_t)ntohs(tcp_header->checksum));
                printf(" urgent_pointer = %u\n", (uint32_t)ntohs(tcp_header->urgent_pointer));
            }
            break;
        case IPProtocol::UDP:
            {
                printf("[UDP Header]\n");
                UDPHeader* udp_header = this->get_transport_layer<UDPHeader>();
                printf(" source_port = %u\n", (uint32_t)ntohs(udp_header->source_port));
                printf(" destination_port = %u\n", (uint32_t)ntohs(udp_header->destination_port));
                printf(" length = %u\n", (uint32_t)ntohs(udp_header->length));
                printf(" checksum = %u\n", (uint32_t)ntohs(udp_header->checksum));
            }
            break;
        default:
            printf("Unsupported protocol for printing\n");
        }

        InBuffer body = this->get_body();
        if (body.get_size())
        {
            printf("[Body]\n");
            printf("Body size: %zu\n", body.get_size());
        }

        printf("-----------=[Packet End]=-----------\n");
    }

    void Packet::make_unique()
    {
        IPHeader* ip_header = this->get_ip_header();
        ip_header->id = (rand() % 65535) + 1;

        this->update_checksums();
    }

    void Packet::update_checksums()
    {
        IPHeader* ip_header = this->get_ip_header();
        ip_header->checksum = calculate_ip_checksum(ip_header);

        switch (this->get_protocol())
        {
        case IPProtocol::TCP:
            {
                TCPHeader* tcp_header = this->get_transport_layer<TCPHeader>();
                tcp_header->checksum = calculate_tcp_checksum(ip_header, tcp_header);
            }
            break;
        case IPProtocol::UDP:
            {
                UDPHeader* udp_header = this->get_transport_layer<UDPHeader>();
                udp_header->checksum = calculate_udp_checksum(ip_header, udp_header);
            }
            break;
        default:
            break;
        }
    }
}