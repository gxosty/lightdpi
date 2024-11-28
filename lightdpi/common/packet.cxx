#include <cstdio>
#include <lightdpi/common/packet.hpp>

namespace ldpi
{
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
}