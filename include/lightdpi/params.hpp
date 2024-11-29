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
        struct _desync_
        {
            Modifier* zero_attack = nullptr;
            Modifier* first_attack = nullptr;
        } desync;
    };
}