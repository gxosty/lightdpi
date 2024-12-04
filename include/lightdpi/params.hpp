#pragma once

#include <vector>

#include "dns/dnsresolver.hpp"
#include "modifiers/modifier.hpp"

namespace ldpi
{
    struct Params
    {
        // for now this does nothing
        bool verbose = false;

        std::vector<DNSResolver*> dns;
        std::vector<Modifier*> modifiers;
    };
}