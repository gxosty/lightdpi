#include <lightdpi/lightdpi.hpp>
#include <lightdpi/dns/doh.hpp>

#include "internal/logger.hpp"

#include <winsock.h>

namespace ldpi
{
    LightDPI::LightDPI(const Params& params)
        : _params(std::move(params)),
          _running{false},
          _handle{nullptr} {}

    LightDPI::~LightDPI()
    {
        if (_handle)
        {
            WinDivertClose(_handle);
            _handle = nullptr;
        }
    }

    void LightDPI::start()
    {
        std::string filter;
        _get_filter(filter);

        internal::Logger logger;
        logger.withfl("WinDivert filter: ", filter).commit();

        HANDLE handle = WinDivertOpen(
            "ip.DstAddr == 209.85.233.147",
            WINDIVERT_LAYER_NETWORK,
            WINDIVERT_PRIORITY_HIGHEST-1000,
            0
        );

        if (handle == INVALID_HANDLE_VALUE)
        {
            throw WinDivertOpenError("Failed opening WinDivert handle");
        }

        WinDivertWrapper divert(handle);

        Packet packet;
        WinDivertAddress address;
        _running = true;

        while (_running)
        {
            if (divert.recv(&packet, &address))
            {
                IPProtocol protocol = packet.get_protocol();

                if (protocol == IPProtocol::UDP)
                {
                    UDPHeader* udp_header = packet.get_transport_layer<UDPHeader>();
                    if (ntohs(udp_header->destination_port) == 53)
                    {
                        if (_do_dns_query(divert, &packet, &address))
                            continue;
                    }
                }
                else if (protocol == IPProtocol::TCP)
                {
                    TCPHeader* tcp_header = packet.get_transport_layer<TCPHeader>();
                    if (ntohs(tcp_header->destination_port) == 443)
                    {
                        namespace f = TCPFlags;
                        if ((tcp_header->flags == f::SYN)
                            && (_params.desync.zero_attack))
                        {
                            if (_do_zero_attack(divert, &packet, &address))
                                continue;
                        }
                        else if ((tcp_header->flags == (f::PSH | f::ACK))
                            && (_params.desync.first_attack))
                        {
                            InBuffer data = packet.get_body();
                            if ((data[0] == 0x16) && (data[5] == 0x01))
                            {
                                logger.withfl("TLSClientHello detected").commit();
                                if (_do_first_attack(divert, &packet, &address))
                                    continue;
                            }
                        }
                    }
                }

                divert.send(packet, &address);
            }
            else
            {
                logger.withfl("divert.recv returned false").commit();
            }
        }
    }

    void LightDPI::stop()
    {
        _running = false;
    }

    void LightDPI::_get_filter(std::string& filter)
    {
        filter.clear();

        filter += "(";

        for (DNSResolver* resolver : _params.dns)
        {
            if (auto doh_resolver = dynamic_cast<DNSOverHTTPS*>(resolver))
            {
                const std::string& doh_ip = doh_resolver->get_ip();

                if (doh_ip.empty())
                {
                    continue;
                }

                if (filter.size() > 1)
                {
                    filter += " and ";
                }

                filter += \
                    "(ip.DstAddr != " + doh_ip + " and ip.SrcAddr != " + doh_ip + ")";
            }
        }

        filter += ")";

        if (filter.size() == 2)
        {
            filter = "true";
        }
    }

    bool LightDPI::_do_dns_query(
        const WinDivertWrapper& divert,
        Packet* packet,
        WinDivertAddress* address)
    {
        // divert.send(packet, address);
        return false;
    }

    bool LightDPI::_do_zero_attack(
        const WinDivertWrapper& divert,
        Packet* packet,
        WinDivertAddress* address)
    {
        if (_params.desync.zero_attack)
        {
            if (address->Outbound && _params.desync.zero_attack->filter_out(packet))
            {
                _params.desync.zero_attack->modify_out(divert, packet, address);
                return true;
            }
            else if (!address->Outbound && _params.desync.zero_attack->filter_in(packet))
            {
                _params.desync.zero_attack->modify_in(divert, packet, address);
                return true;
            }
        }

        return false;
    }

    bool LightDPI::_do_first_attack(
        const WinDivertWrapper& divert,
        Packet* packet,
        WinDivertAddress* address)
    {
        if (_params.desync.first_attack)
        {
            if (address->Outbound && _params.desync.first_attack->filter_out(packet))
            {
                _params.desync.first_attack->modify_out(divert, packet, address);
                return true;
            }
            else if (!address->Outbound && _params.desync.first_attack->filter_in(packet))
            {
                _params.desync.first_attack->modify_in(divert, packet, address);
                return true;
            }
        }

        return false;
    }
}