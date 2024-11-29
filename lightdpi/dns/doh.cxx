#include <lightdpi/dns/doh.hpp>
#include <lightdpi/utils.hpp>

#include <curl/curl.h>

#include "../internal/helpers.hpp"

namespace ldpi
{
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

        if (!_ip.empty())
        {
            int port = get_port_by_protocol(_url);

            if (!_front.empty())
            {
                std::string host;
                get_url_host(_url, host);
                _resolution_list = curl_slist_append(
                    _resolution_list,
                    (host + ":" + std::to_string(port) + ":" + _ip).c_str()
                );
            }
            else
            {
                _resolution_list = curl_slist_append(
                    _resolution_list,
                    (_front + ":" + std::to_string(port) + ":" + _ip).c_str()
                );
            }

            curl_easy_setopt(_curl, CURLOPT_RESOLVE, _resolution_list);
        }

        if (!_front.empty())
        {
            std::string new_url;
            replace_url_host(_url, _front, new_url);
            curl_easy_setopt(_curl, CURLOPT_URL, new_url.c_str());
        }
        else
        {
            curl_easy_setopt(_curl, CURLOPT_URL, _url.c_str());
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

    void DNSOverHTTPS::resolve(Packet* in_packet, Packet* out_packet)
    {

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