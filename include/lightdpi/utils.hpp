#pragma once

#include <string>
#include <curl/curl.h>

namespace ldpi
{
    void get_url_host(const std::string& url, std::string& out_host);

    void replace_url_host(
        const std::string& url,
        const std::string& new_host,
        std::string& out_url);

    int get_port_by_protocol(const std::string& url);

    void generate_random_bytes(char* buffer, int count);
}