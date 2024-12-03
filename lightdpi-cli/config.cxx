#include <fstream>
#include <nlohmann/json.hpp>
#include "exceptions.hpp"

#include "config.hpp"

#include <lightdpi/dns/dnsresolver.hpp>
#include <lightdpi/dns/doh.hpp>

#include <lightdpi/modifiers/modifier.hpp>
#include <lightdpi/modifiers/fakettl.hpp>
#include <lightdpi/modifiers/fakechecksum.hpp>

void load_from_config(fs::path config_path, ldpi::Params& params)
{
    if (!fs::exists(config_path) or !fs::is_regular_file(config_path))
    {
        throw FileNotFoundError(config_path.string());
    }

    std::ifstream config_file(config_path);

    if (!config_file.is_open())
    {
        throw std::runtime_error("Couldn't open config file: " + config_path.string());
    }

    nlohmann::json config;
    config_file >> config;
    config_file.close();

    if (config.contains("dns"))
    {
        for (auto item : config["dns"].items())
        {
            std::string dns_type = item.value()["type"].get<std::string>();

            if (dns_type == "doh")
            {
                auto& dns_params = item.value()["params"];

                std::string dns_url = dns_params["url"];
                std::string dns_ip;
                std::string dns_front;

                if (dns_params.contains("ip"))
                {
                    dns_ip = dns_params["ip"].get<std::string>();
                }

                if (dns_params.contains("front"))
                {
                    dns_front = dns_params["front"].get<std::string>();
                }

                ldpi::DNSOverHTTPS* doh = new ldpi::DNSOverHTTPS(dns_url, dns_ip, dns_front);
                params.dns.push_back(doh);
            }
            else
            {
                throw std::runtime_error("Invalid dns type: " + dns_type);
            }
        }
    }

    if (config.contains("desync"))
    {
        if (config["desync"].contains("zero-attack"))
        {
            // TODO
        }
        if (config["desync"].contains("https-first-attack"))
        {
            auto& first_attack = config["desync"]["https-first-attack"];
            std::string first_attack_type = first_attack["type"].get<std::string>();

            if (first_attack_type.rfind("fake-", 0) != std::string::npos)
            {
                auto& first_attack_params = first_attack["params"];

                std::string fake_packet_type_str = first_attack_params["fake-packet-type"].get<std::string>();

                ldpi::FakeModifier::Type fake_packet_type;

                if (fake_packet_type_str == "fake-random")
                {
                    fake_packet_type = ldpi::FakeModifier::Type::FAKE_RANDOM;
                }
                else if (fake_packet_type_str == "fake-decoy")
                {
                    fake_packet_type = ldpi::FakeModifier::Type::FAKE_DECOY;
                }
                else
                {
                    throw std::runtime_error("Invalid fake packet type for FakeTTL");
                }

                if (first_attack_type == "fake-ttl")
                {
                    int fake_packet_ttl  = first_attack_params["fake-packet-ttl"].get<int>();
                    params.desync.first_attack = new ldpi::FakeTTLModifier(fake_packet_type, fake_packet_ttl);
                }
                else if (first_attack_type == "fake-checksum")
                {
                    params.desync.first_attack = new ldpi::FakeChecksumModifier(fake_packet_type);
                }
                else
                {
                    throw std::runtime_error("Invalid Fake modifier: " + first_attack_type);
                }
            }
            else
            {
                throw std::runtime_error("Invalid first attack type: " + first_attack_type);
            }
        }
    }
}