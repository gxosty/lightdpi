#pragma once

#include "dns/dnsresolver.hpp"
#include "modifiers/modifier.hpp"

#include <vector>
#include <memory>

namespace ldpi
{
    struct Params
    {
        std::vector<std::unique_ptr<DNSResolver>> dns;
        struct desync
        {
            std::unique_ptr<Modifier> zero_attack;
            std::unique_ptr<Modifier> first_attack;
        };
    };
}