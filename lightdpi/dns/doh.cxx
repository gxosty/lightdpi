#include <lightdpi/dns/doh.hpp>
#include <lightdpi/utils.hpp>

#include <curl/curl.h>
#include <base64.hpp>

#include "../internal/helpers.hpp"
#include "../internal/logger.hpp"

#include <cstring>

namespace ldpi
{
    internal::Logger logger;

    DNSOverHTTPS::DNSOverHTTPS(
        const std::string& url,
        const std::string& ip,
        const std::string& front
    ) : _url{url}, _ip{ip}, _front{front},
        _resolution_list{nullptr}
    {
        _curl = curl_easy_init();
        curl_easy_setopt(_curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(_curl, CURLOPT_WRITEFUNCTION, &internal::_write_function);
        curl_easy_setopt(_curl, CURLOPT_CONNECTTIMEOUT, 5L);

        if (!_ip.empty())
        {
            int port = get_port_by_protocol(_url);

            if (!_front.empty())
            {
                std::string r = (_front + ":" + std::to_string(port) + ":" + _ip);
                _resolution_list = curl_slist_append(
                    _resolution_list,
                    r.c_str()
                );
            }
            else
            {
                std::string host;
                get_url_host(_url, host);
                std::string r = (host + ":" + std::to_string(port) + ":" + _ip);
                _resolution_list = curl_slist_append(
                    _resolution_list,
                    r.c_str()
                );
            }

            curl_easy_setopt(_curl, CURLOPT_RESOLVE, _resolution_list);
        }

        if (!_front.empty())
        {
            curl_easy_setopt(_curl, CURLOPT_SSL_VERIFYPEER, 0L);
            curl_easy_setopt(_curl, CURLOPT_SSL_VERIFYHOST, 0L);

            std::string new_url;
            replace_url_host(_url, _front, new_url);
            // curl_easy_setopt(_curl, CURLOPT_URL, new_url.c_str());
            _query_url = new_url + "?dns=";
        }
        else
        {
            // curl_easy_setopt(_curl, CURLOPT_URL, _url.c_str());
            _query_url = _url + "?dns=";
        }
    }

    DNSOverHTTPS::~DNSOverHTTPS()
    {
        if (_resolution_list)
        {
            curl_slist_free_all(_resolution_list);
            _resolution_list = nullptr;
        }

        curl_easy_cleanup(_curl);
    }

    bool DNSOverHTTPS::resolve(Packet* in_packet, Packet* out_packet)
    {
        out_packet->copy_from(in_packet->get_data(), in_packet->get_size());

        std::string output;
        std::string b64_dns_query;
        std::string url;

        InBuffer in_buffer = in_packet->get_body();

        std::string dns_query(in_buffer.get_data(), in_buffer.get_size());
        std::string bdq = base64::to_base64(dns_query);
        b64_dns_query.reserve(bdq.size());

        for (auto& c : bdq)
        {
            if (c == '=') continue;

            if (c == '+')
            {
                b64_dns_query.append(1, '-');
                continue;
            }

            if (c == '/')
            {
                b64_dns_query.append(1, '_');
                continue;
            }

            b64_dns_query.append(1, c);
        }

        url = _query_url + b64_dns_query;

        curl_easy_setopt(_curl, CURLOPT_WRITEDATA, reinterpret_cast<void*>(&output));
        curl_easy_setopt(_curl, CURLOPT_URL, url.c_str());

        CURLcode curle_code = CURLE_OK;
        int status_code = 0;
        int retries = 3;

        do {
            curle_code = curl_easy_perform(_curl);
            curl_easy_getinfo(_curl, CURLINFO_RESPONSE_CODE, &status_code);
        } while ((curle_code != CURLE_OK) && ((--retries) > 0));

        if ((curle_code == CURLE_OK) && (status_code == 200))
        {
            InBuffer out_buffer = out_packet->get_body();
            memcpy(out_buffer.get_data(), output.data(), output.size());
            out_packet->set_size(
                output.size() +
                ((uintptr_t)out_buffer.get_data() - (uintptr_t)out_packet->get_ip_header())
            );
            IPHeader* out_ip_header = out_packet->get_ip_header();
            out_ip_header->length = htons(out_packet->get_size());
            UDPHeader* out_udp_header = out_packet->get_transport_layer<UDPHeader>();
            out_udp_header->length = htons(output.size() + 8);
            out_packet->make_unique();
            out_packet->reverse_direction();
            return true;
        }

        logger.withfl("DNS Query error").commit();
        return false;
    }

    const std::string& DNSOverHTTPS::get_url() const
    {
        return _url;
    }

    const std::string& DNSOverHTTPS::get_ip() const
    {
        return _ip;
    }

    const std::string& DNSOverHTTPS::get_front() const
    {
        return _front;
    }
}