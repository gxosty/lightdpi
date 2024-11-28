#pragma once

#include <windivert/windivert.h>
#include "buffer.hpp"

namespace ldpi
{
    typedef WINDIVERT_ADDRESS WinDivertAddress;

    class WinDivertWrapper
    {
    public:
        WinDivertWrapper(HANDLE handle) : _handle{handle} {}
        ~WinDivertWrapper();

        bool recv(InBuffer* buffer, WinDivertAddress* address = nullptr);
        bool send(const InBuffer& buffer, WinDivertAddress* address = nullptr);

    private:
        HANDLE _handle;

    };
}