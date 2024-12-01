#pragma once

#include <string>
#include <stdexcept>

class FileNotFoundError : public std::runtime_error
{
public:
    FileNotFoundError(const std::string& filename)
        : std::runtime_error("'" + filename + "' not found") {}
};

class InvalidConfigError : public std::runtime_error
{
public:
    InvalidConfigError(const std::string& filename)
        : std::runtime_error("'" + filename + "' is not valid config file") {}
};