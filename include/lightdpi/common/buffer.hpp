#pragma once

#include "inbuffer.hpp"

#include <cstdint>

#ifndef LDPI_BUFFER_MAX_SIZE
    #define LDPI_BUFFER_MAX_SIZE 4096
#endif

namespace ldpi
{
    /**
     * Creates fixed buffer size of LDPI_BUFFER_MAX_SIZE
     */

    class Buffer : public InBuffer
    {
    public:
        Buffer();

        void copy_from(char* data, size_t size);

        char operator[](uint32_t idx) const;
        char* operator+(uint32_t offset) const;

    protected:
        char _buffer[LDPI_BUFFER_MAX_SIZE];
    };
}