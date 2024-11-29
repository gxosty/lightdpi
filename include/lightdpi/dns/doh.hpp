#pragma once

#include <string>
#include <curl/curl.h>

#include "../common/packet.hpp"
#include "dnsresolver.hpp"

namespace ldpi
{
    class DNSOverHTTPS : public DNSResolver
    {
    public:
        DNSOverHTTPS(
            const std::string& url,
            const std::string& ip = "",
            const std::string& front = ""
        );

        ~DNSOverHTTPS() override;

        void resolve(Packet* in_packet, Packet* out_packet) override;

        const std::string& get_url() const;
        const std::string& get_ip() const;
        const std::string& get_front() const;

    private:
        CURL* _curl;
        curl_slist* _resolution_list;

        std::string _url;
        std::string _ip;
        std::string _front;

    };
}