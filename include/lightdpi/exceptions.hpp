#pragma once

#include <string>
#include <stdexcept>

namespace ldpi
{
    class WinDivertOpenError : public std::runtime_error
    {
    public:
        WinDivertOpenError(const std::string& msg) : std::runtime_error(msg) {}
    };
}