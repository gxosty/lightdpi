#pragma once

#include "fake.hpp"

namespace ldpi
{
    class FakeACKModifier : public FakeModifier
    {
    public:
        FakeACKModifier(FakeModifier::Type fake_packet_type);

        bool filter_out(Packet* packet) override;

        void modify_out(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address) override;
    };
}