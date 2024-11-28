#include <lightdpi/common/windivertwrapper.hpp>

namespace ldpi
{
    WinDivertWrapper::~WinDivertWrapper()
    {
        WinDivertClose(_handle);
    }

    bool WinDivertWrapper::recv(InBuffer* buffer, WinDivertAddress* address)
    {
        uint32_t recv_size;
        bool res = WinDivertRecv(
            _handle,
            reinterpret_cast<void*>(buffer->get_data()),
            LDPI_BUFFER_MAX_SIZE,
            &recv_size,
            address
        );
        buffer->set_size(recv_size);
        return res;
    }

    bool WinDivertWrapper::send(const InBuffer& buffer, WinDivertAddress* address)
    {
        return WinDivertSend(
            _handle,
            reinterpret_cast<void*>(buffer.get_data()),
            buffer.get_size(),
            nullptr,
            address
        );
    }
}