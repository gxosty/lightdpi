#pragma once

#include "../common/windivertwrapper.hpp"
#include "../common/packet.hpp"

namespace ldpi
{
    class Modifier
    {
    public:
        // check if the packet is what modifier is looking for
        virtual bool filter_in(Packet* packet) = 0;
        virtual bool filter_out(Packet* packet) = 0;

        // modify filtered packet
        virtual void modify_in(Packet* packet, const WinDivertWrapper& handle) = 0;
        virtual void modify_out(Packet* packet, const WinDivertWrapper& handle) = 0;
    };
}