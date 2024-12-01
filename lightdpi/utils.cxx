#include <lightdpi/utils.hpp>

#include <random>

namespace ldpi
{
    void get_url_host(const std::string& url, std::string& out_host)
    {
        CURLU* _url = curl_url();
        if (!_url) return;

        if (curl_url_set(_url, CURLUPART_URL, url.c_str(), 0))
        {
            curl_url_cleanup(_url);
            return;
        }

        char* _host = nullptr;
        curl_url_get(_url, CURLUPART_HOST, &_host, 0);

        out_host = std::string(_host);

        curl_free(_host);
        curl_url_cleanup(_url);
    }

    void replace_url_host(
        const std::string& url,
        const std::string& new_host,
        std::string& out_url)
    {
        // lazy to check for errors, but it will most likely work :P

        CURLU* _url = curl_url();
        curl_url_set(_url, CURLUPART_URL, url.c_str(), 0);
        curl_url_set(_url, CURLUPART_HOST, new_host.c_str(), 0);

        char* new_url = nullptr;
        curl_url_get(_url, CURLUPART_URL, &new_url, 0);

        out_url = std::string(new_url);

        curl_free(new_url);
        curl_url_cleanup(_url);
    }

    int get_port_by_protocol(const std::string& url)
    {
        if (url.rfind("http://", 0) != std::string::npos)
        {
            return 80;
        }
        else if (url.rfind("https://", 1) != std::string::npos)
        {
            return 443;
        }

        return 0;
    }

    void generate_random_bytes(char* buffer, int count)
    {
        for (int i = 0; i < count; i++)
            buffer[i] = rand() % 256;
    }

    bool is_tls_client_hello(const InBuffer& data)
    {
        // return ((data.get_size() > 0)
        //     && ((data[0] == 0x16) || (data[0] == 0x17))
        //     && (data[1] == 0x03)
        //     && (data[2] < 0xA)
        //     && (data[5] == 0x01));

        // return ((data[0] == 0x16) && (data[5] == 0x01));

        return (
            ((data[0] == 0x16)
             && (data[1] == 0x03)
             && (
                    (data[2] == 0x01)
                    || (data[2] == 0x03)
                )
            )
        );
    }
}