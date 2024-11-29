#pragma once

#include "modifier.hpp"

namespace ldpi
{
    class FakeTTLModifier : public Modifier
    {
    public:
        enum class Type
        {
            FAKE_COPY,
            FAKE_DECOY,
            FAKE_RANDOM
        };

    public:
        FakeTTLModifier(Type fake_packet_type, int fake_packet_ttl);

        bool filter_out(Packet* packet) override;

        void modify_out(
            const WinDivertWrapper& divert,
            Packet* packet,
            WinDivertAddress* address) override;

    private:
        Type _fake_packet_type;
        int _fake_packet_ttl;
    };
}