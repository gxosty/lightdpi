#pragma once

#include <vector>

#include "dns/dnsresolver.hpp"
#include "modifiers/modifier.hpp"

namespace ldpi
{
    struct Params
    {
        bool verbose = false;
        std::vector<DNSResolver*> dns;
        struct desync
        {
            Modifier* zero_attack = nullptr;
            Modifier* first_attack = nullptr;
        };
    };
}