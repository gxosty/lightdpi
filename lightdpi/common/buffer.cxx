#include <lightdpi/common/buffer.hpp>

#include <cstdlib>
#include <cstring>

namespace ldpi
{
    Buffer::Buffer() : InBuffer(reinterpret_cast<char*>(&_buffer), 0)
    {
        memset(const_cast<char*>(_buffer), 0, LDPI_BUFFER_MAX_SIZE);
    }

    void Buffer::copy_from(char* data, size_t size)
    {
        _size = size;
        memcpy(_data, data, size);
    }

    char Buffer::operator[](uint32_t idx) const
    {
        return _buffer[idx];
    }

    char* Buffer::operator+(uint32_t offset) const
    {
        return const_cast<char*>(_buffer) + offset;
    }
}