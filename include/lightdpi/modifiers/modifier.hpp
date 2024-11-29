#pragma once

#include "../common/windivertwrapper.hpp"
#include "../common/packet.hpp"

namespace ldpi
{
    class Modifier
    {
    public:
        virtual ~Modifier() = default;

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
    };
}