#include "helpers.hpp"

namespace ldpi::internal
{
    size_t _write_function(void* ptr, size_t sz, size_t n, std::string* out)
    {
        size_t total = sz * n;
        out->append(reinterpret_cast<char*>(ptr), total);
        return total;
    }
}