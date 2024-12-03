#pragma once

#include "modifier.hpp"

namespace ldpi
{
    class FakeModifier : public Modifier
    {
    public:
        enum class Type
        {
            FAKE_DECOY,
            FAKE_RANDOM
        };

    public:
        FakeModifier(Type fake_packet_type)
            : _fake_packet_type{fake_packet_type} {}

        Type get_fake_packet_type() const
        {
            return _fake_packet_type;
        }

    protected:
        Type _fake_packet_type;
    };
}