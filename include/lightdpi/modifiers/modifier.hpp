#pragma once

#include <cstdint>

#include "../common/windivertwrapper.hpp"
#include "../common/packet.hpp"

namespace ldpi
{
    namespace ModifierFlags {
        static constexpr uint8_t TCP_HANDSHAKE    = 1;
        static constexpr uint8_t HTTP_REQUEST     = 1 << 1;
        static constexpr uint8_t TLS_CLIENT_HELLO = 1 << 2;
        static constexpr uint8_t OTHER            = 1 << 3;
        static constexpr uint8_t ALL              = (1 << 4) - 1;
    };

    class Modifier
    {
    public:
        Modifier(uint8_t flags) : _flags{flags} {}
        virtual ~Modifier() = default;

        inline uint8_t get_flags() const
        {
            return _flags;
        };

        // check if the packet is what modifier is looking for
        virtual bool filter_in(Packet* packet) { return false; }
        virtual bool filter_out(Packet* packet) { return false; }

        // modify filtered packet
        virtual void modify_in(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address) {}

        virtual void modify_out(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address) {}

    protected:
        uint8_t _flags;
    };
}