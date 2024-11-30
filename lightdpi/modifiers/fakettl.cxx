#include <lightdpi/utils.hpp>
#include <lightdpi/modifiers/fakettl.hpp>
#include <lightdpi/net/ip.hpp>
#include <lightdpi/net/tcp.hpp>
#include <lightdpi/net/checksum.hpp>

#include "../internal/data.hpp"

#include <cstring>

namespace ldpi
{
    FakeTTLModifier::FakeTTLModifier(Type fake_packet_type, int fake_packet_ttl)
            : _fake_packet_type{fake_packet_type}
            , _fake_packet_ttl{fake_packet_ttl} {}

    bool FakeTTLModifier::filter_out(Packet* packet)
    {
        if (packet->get_protocol() != IPProtocol::TCP)
        {
            return false;
        }

        TCPHeader* tcp_header = packet->get_transport_layer<TCPHeader>();

        if (~(tcp_header->flags) & TCPFlags::PSH)
        {
            return false;
        }

        InBuffer data = packet->get_body();

        if ((data[0] == 0x16) && (data[5] == 0x01))
        {
            return true;
        }

        return false;
    }

    void FakeTTLModifier::modify_out(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address)
    {
        Packet* fake_packet = nullptr;

        if (_fake_packet_type == Type::FAKE_COPY)
        {
            fake_packet = packet->copy();
        }
        else if (_fake_packet_type == Type::FAKE_DECOY)
        {
            fake_packet = packet->copy();
            InBuffer body = fake_packet->get_body();
            char* data = body.get_data();
            memcpy(
                data,
                internal::fake_tls_client_hello,
                internal::fake_tls_client_hello_size
            );
            IPHeader* ip_header = fake_packet->get_ip_header();
            size_t headers_size = (uintptr_t)data - (uintptr_t)ip_header;
            fake_packet->set_size(internal::fake_tls_client_hello_size + headers_size);
        }
        else if (_fake_packet_type == Type::FAKE_RANDOM)
        {
            fake_packet = packet->copy();
            InBuffer body = fake_packet->get_body();
            char* data = body.get_data();

            do {
                generate_random_bytes(data, 256);
            } while ((data[0] == 0x16) && (data[5] == 0x01));

            IPHeader* ip_header = fake_packet->get_ip_header();
            size_t headers_size = (uintptr_t)data - (uintptr_t)ip_header;
            fake_packet->set_size(256 + headers_size);
        }
        else
        {
            return;
        }

        IPHeader* ip_header = fake_packet->get_ip_header();
        TCPHeader* tcp_header = fake_packet->get_transport_layer<TCPHeader>();
        ip_header->ttl = _fake_packet_ttl;

        ip_header->checksum = calculate_ip_checksum(ip_header);
        tcp_header->checksum = calculate_tcp_checksum(ip_header, tcp_header);

        divert.send(*fake_packet, address);
        divert.send(*packet, address);
    }
}