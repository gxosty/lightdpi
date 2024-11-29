#pragma once

#include <cstdint>

namespace ldpi
{
    class InBuffer
    {
    public:
        InBuffer(char* data, size_t size) : _data{data}, _size{size} {};

        char* get_data() const { return _data; }
        size_t get_size() const { return _size; }
        void set_size(size_t size) { _size = size; }

        inline char operator[](uint32_t idx) const
        {
            return _data[idx];
        }

        inline char* operator+(uint32_t offset) const
        {
            return _data + offset;
        }

    protected:
        char* _data;
        size_t _size;
    };
}