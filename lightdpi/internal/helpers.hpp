#pragma once

#include <cstdint>
#include <string>

namespace ldpi::internal
{
    size_t _write_function(void* ptr, size_t sz, size_t n, std::string* out);
}