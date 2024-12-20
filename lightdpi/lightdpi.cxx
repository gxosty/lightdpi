#include <cstring>
#include <cstdlib>
#include <thread>

#include <lightdpi/lightdpi.hpp>
#include <lightdpi/dns/doh.hpp>

#include <lightdpi/utils.hpp>
#include "internal/logger.hpp"

#include <winsock.h>

namespace ldpi
{
    LightDPI::LightDPI(const Params& params)
        : _params(std::move(params)),
          _running{false},
          _handle{nullptr},
          _dns_handle{nullptr} {}

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

        _handle = WinDivertOpen(
            filter.c_str(),
            WINDIVERT_LAYER_NETWORK,
            WINDIVERT_PRIORITY_HIGHEST-1000,
            0
        );

        if (_handle == INVALID_HANDLE_VALUE)
        {
            _handle = nullptr;
            throw WinDivertOpenError("Failed opening WinDivert handle");
        }

        {
            // WinDivertWrapper automatically closes handle upon destruction
            WinDivertWrapper divert(_handle);

            Packet packet;
            WinDivertAddress address;
            _running = true;

            std::thread dns_loop_th(&LightDPI::_dns_loop, this);

            while (_running)
            {
                if (divert.recv(&packet, &address))
                {
                    #define fl ModifierFlags

                    if (packet.is_tcp_syn())
                    {
                        if (_apply_modifier(
                            divert, &packet, &address,
                            fl::TCP_HANDSHAKE | fl::ALL
                        )) continue;
                    }

                    if (packet.is_http_request())
                    {
                        if (_apply_modifier(
                            divert, &packet, &address,
                            fl::HTTP_REQUEST | fl::ALL
                        )) continue;
                    }

                    if (packet.is_tls_client_hello())
                    {
                        if (_apply_modifier(
                            divert, &packet, &address,
                            fl::TLS_CLIENT_HELLO | fl::ALL
                        )) continue;
                    }

                    if (_apply_modifier(
                        divert, &packet, &address,
                        fl::OTHER | fl::ALL
                    )) continue;

                    #undef fl

                    divert.send(packet, &address);
                }
                else
                {
                    if (GetLastError() != ERROR_NO_DATA)
                    {
                        logger.withfl("divert.recv error: ", (int)GetLastError()).commit();
                    }
                }
            }

            dns_loop_th.join();
        }

        _handle = nullptr;
    }

    void LightDPI::stop()
    {
        _running = false;
        WinDivertShutdown(_handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertShutdown(_dns_handle, WINDIVERT_SHUTDOWN_BOTH);
    }

    void LightDPI::_dns_loop()
    {
        std::string filter = "outbound and udp.DstPort == 53 and !impostor";

        internal::Logger logger;
        logger.withfl("WinDivert DNS filter: ", filter).commit();

        _dns_handle = WinDivertOpen(
            filter.c_str(),
            WINDIVERT_LAYER_NETWORK,
            WINDIVERT_PRIORITY_HIGHEST-1001,
            0
        );

        if (_dns_handle == INVALID_HANDLE_VALUE)
        {
            _dns_handle = nullptr;
            throw WinDivertOpenError("Failed opening WinDivert handle (DNS)");
        }

        {
            WinDivertWrapper divert(_dns_handle);

            Packet packet;
            WinDivertAddress address;

            while (_running)
            {
                if (divert.recv(&packet, &address))
                {
                    if (_do_dns_query(divert, &packet, &address))
                        continue;

                    divert.send(packet, &address);
                }
                else
                {
                    if (GetLastError() != ERROR_NO_DATA)
                    {
                        logger.withfl("(DNS) divert.recv error: ", (int)GetLastError()).commit();
                    }
                }
            }
        }

        _dns_handle = nullptr;
    }

    void LightDPI::_get_filter(std::string& filter)
    {
        filter.clear();

        filter += "tcp and !impostor"
                  " and (ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1)";

        // Exclude DNS-over-HTTPS ips
        if (!_params.dns.empty())
        {
            filter += " and (";
            bool added = false;
            for (DNSResolver* resolver : _params.dns)
            {
                if (auto doh_resolver = dynamic_cast<DNSOverHTTPS*>(resolver))
                {
                    const std::string& doh_ip = doh_resolver->get_ip();

                    if (doh_ip.empty())
                    {
                        continue;
                    }

                    if (added)
                    {
                        filter += " and ";
                    }

                    added = true;
                    filter += \
                        "(ip.DstAddr != " + doh_ip + " and ip.SrcAddr != " + doh_ip + ")";
                }
            }

            filter += ")";
        }
    }

    bool LightDPI::_do_dns_query(
        const WinDivertWrapper& divert,
        Packet* packet,
        WinDivertAddress* address)
    {
        Packet out_packet;

        for (auto dns : _params.dns)
        {
            if (dns->resolve(packet, &out_packet))
            {
                address->Outbound = 0;
                divert.send(out_packet, address);
                return true;
            }
        }

        return false;
    }

    bool LightDPI::_apply_modifier(
        const WinDivertWrapper& divert,
        Packet* packet,
        WinDivertAddress* address,
        uint8_t modifier_flags)
    {
        for (Modifier* modifier : _params.modifiers)
        {
            if (modifier->get_flags() & modifier_flags)
            {
                if (_apply_modifier(divert, packet, address, modifier))
                {
                    return true;
                }
            }
        }

        return false;
    }

    bool LightDPI::_apply_modifier(
        const WinDivertWrapper& divert,
        Packet* packet,
        WinDivertAddress* address,
        Modifier* modifier)
    {
        if (address->Outbound && modifier->filter_out(packet))
        {
            modifier->modify_out(divert, packet, address);
            return true;
        }
        else if (!address->Outbound && modifier->filter_in(packet))
        {
            modifier->modify_in(divert, packet, address);
            return true;
        }

        return false;
    }
}