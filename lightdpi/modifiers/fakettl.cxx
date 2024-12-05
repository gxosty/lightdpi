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
    FakeTTLModifier::FakeTTLModifier(FakeModifier::Type fake_packet_type, int fake_packet_ttl) :
        FakeModifier(
            fake_packet_type,
            ModifierFlags::HTTP_REQUEST |
            ModifierFlags::TLS_CLIENT_HELLO),
        _fake_packet_ttl{fake_packet_ttl} {}

    bool FakeTTLModifier::filter_out(Packet* packet)
    {
        return packet->is_tls_client_hello() || packet->is_http_request();
    }

    void FakeTTLModifier::modify_out(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address)
    {
        size_t fake_bytes_size = 0;

        _fake_packet.copy_from(packet->get_data(), packet->get_size());
        InBuffer body = _fake_packet.get_body();
        char* data = body.get_data();

        if (_fake_packet_type == FakeModifier::Type::FAKE_DECOY)
        {
            memcpy(
                data,
                internal::fake_tls_client_hello,
                internal::fake_tls_client_hello_size
            );
            fake_bytes_size = internal::fake_tls_client_hello_size;
        }
        else if (_fake_packet_type == FakeModifier::Type::FAKE_RANDOM)
        {
            fake_bytes_size = (rand() % 256) + 256;

            do {
                generate_random_bytes(data, fake_bytes_size);
            } while ((data[0] == 0x16) && (data[5] == 0x01));
        }
        else
        {
            return;
        }

        IPHeader* ip_header = _fake_packet.get_ip_header();
        size_t headers_size = (uintptr_t)data - (uintptr_t)ip_header;
        ip_header->length = htons(fake_bytes_size + headers_size);
        _fake_packet.set_size(fake_bytes_size + headers_size);
        ip_header->ttl = _fake_packet_ttl;

        TCPHeader* tcp_header = _fake_packet.get_transport_layer<TCPHeader>();

        ip_header->checksum = calculate_ip_checksum(ip_header);
        tcp_header->checksum = calculate_tcp_checksum(ip_header, tcp_header);

        divert.send(_fake_packet, address);
        divert.send(*packet, address);
    }

    int FakeTTLModifier::get_fake_packet_ttl() const
    {
        return _fake_packet_ttl;
    }
}