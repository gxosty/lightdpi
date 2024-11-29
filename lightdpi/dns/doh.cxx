#include <dns/doh.h>

namespace ldpi
{
    DNSOverHTTPS::DNSOverHTTPS(
        const std::string& address,
        const std::string& ip,
        const std::string& front
    ) : _address{address}, _ip{ip}, _front{front},
        _resolution_list{nullptr}
    {
        _curl = curl_easy_init();
        curl_easy_setopt(_curl, CURLOPT_URL, _address.c_str());
        curl_easy_setopt(_curl, CURLOPT_FOLLOW_LOCATION, 1L);

        if (!_ip.empty())
        {
            _resolution_list = curl_slist_append(_resolution_list, );
            curl_easy_setopt(_curl, CURLOPT_RESOLVE, );
        }
    }
}