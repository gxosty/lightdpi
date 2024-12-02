#include <random>
#include <cstring>

#include <lightdpi/utils.hpp>
#include <lightdpi/modifiers/fakettl.hpp>
#include <lightdpi/net/ip.hpp>
#include <lightdpi/net/tcp.hpp>
#include <lightdpi/net/checksum.hpp>

#include "../internal/data.hpp"
#include "../internal/logger.hpp"

namespace ldpi
{
    FakeTTLModifier::FakeTTLModifier(Type fake_packet_type, int fake_packet_ttl)
            : _fake_packet_type{fake_packet_type}
            , _fake_packet_ttl{fake_packet_ttl} {}

    bool FakeTTLModifier::filter_out(Packet* packet)
    {
        internal::Logger logger;
        if (packet->get_protocol() != IPProtocol::TCP)
        {
            return false;
        }

        TCPHeader* tcp_header = packet->get_transport_layer<TCPHeader>();

        namespace f = TCPFlags;
        if ((tcp_header->flags != f::ACK) && (tcp_header->flags != (f::PSH | f::ACK)))
        {
            return false;
        }

        InBuffer data = packet->get_body();

        if (is_tls_client_hello(data))
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
        size_t fake_bytes_size = 0;

        fake_packet = packet->copy();
        InBuffer body = fake_packet->get_body();
        char* data = body.get_data();

        if (_fake_packet_type == Type::FAKE_DECOY)
        {
            memcpy(
                data,
                internal::fake_tls_client_hello,
                internal::fake_tls_client_hello_size
            );
            fake_bytes_size = internal::fake_tls_client_hello_size;
        }
        else if (_fake_packet_type == Type::FAKE_RANDOM)
        {
            fake_bytes_size = (rand() % 256) + 256;

            do {
                generate_random_bytes(data, 513);
            } while ((data[0] == 0x16) && (data[5] == 0x01));
        }
        else
        {
            return;
        }

        IPHeader* ip_header = fake_packet->get_ip_header();
        size_t headers_size = (uintptr_t)data - (uintptr_t)ip_header;
        ip_header->length = htons(513 + headers_size);
        fake_packet->set_size(513 + headers_size);
        ip_header->ttl = _fake_packet_ttl;

        TCPHeader* tcp_header = fake_packet->get_transport_layer<TCPHeader>();

        ip_header->checksum = calculate_ip_checksum(ip_header);
        tcp_header->checksum = calculate_tcp_checksum(ip_header, tcp_header);

        divert.send(*fake_packet, address);
        divert.send(*packet, address);

        delete fake_packet;
    }

    FakeTTLModifier::Type FakeTTLModifier::get_fake_packet_type() const
    {
        return _fake_packet_type;
    }

    int FakeTTLModifier::get_fake_packet_ttl() const
    {
        return _fake_packet_ttl;
    }
}