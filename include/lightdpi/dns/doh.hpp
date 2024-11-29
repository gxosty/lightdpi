#pragma once

#include <string>
#include <curl/curl.h>

namespace ldpi
{
    class DNSOverHTTPS : public DNSResolver
    {
    public:
        DNSOverHTTPS(
            const std::string& address,
            const std::string& ip = "",
            const std::string& front = ""
        );

        void resolve(Packet* in_packet, Packet* out_packet) override;

    private:
        CURL* _curl;
        curl_slist* _resolution_list;

        std::string _address;
        std::string _ip;
        std::string _front;

    };
}