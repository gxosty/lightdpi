#pragma once

#include "fake.hpp"

namespace ldpi
{
    class FakeTTLModifier : public FakeModifier
    {
    public:
        FakeTTLModifier(
            FakeModifier::Type fake_packet_type,
            int fake_packet_ttl
        );

        bool filter_out(Packet* packet) override;

        void modify_out(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address) override;

        int get_fake_packet_ttl() const;

    private:
        int _fake_packet_ttl;
        Packet _fake_packet;
    };
}