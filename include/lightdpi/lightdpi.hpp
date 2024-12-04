#pragma once

#include "exceptions.hpp"
#include "params.hpp"
#include "common/windivertwrapper.hpp"
#include "dns/dnsresolver.hpp"
#include "modifiers/modifier.hpp"

#include <string>

namespace ldpi
{
    class LightDPI
    {
    public:
        // LightDPI takes ownership of Params
        LightDPI(const Params& params);
        ~LightDPI();

        void start();
        void stop();

    private:
        void _dns_loop();

    private:
        HANDLE _handle;
        HANDLE _dns_handle;
        Params _params;
        bool _running;

    private:
        void _get_filter(std::string& filter);

        bool _do_dns_query(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address);

        bool _apply_modifier(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address,
            uint8_t modifier_flags);

        bool _apply_modifier(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address,
            Modifier* modifier);
    };
}