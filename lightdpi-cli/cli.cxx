#include <iostream>
#include <filesystem>
#include <map>
#include <unordered_map>
#include <string>
#include <signal.h>
#include <argparse/argparse.hpp>
#include "exceptions.hpp"
#include "config.hpp"

#include <lightdpi/lightdpi.hpp>

#include <lightdpi/dns/doh.hpp>

#include <lightdpi/modifiers/fakeack.hpp>
#include <lightdpi/modifiers/fakettl.hpp>
#include <lightdpi/modifiers/fakechecksum.hpp>

namespace fs = std::filesystem;

static ldpi::LightDPI* light = nullptr;

void handle_sigint(int sig)
{
    if (light)
    {
        std::cout << "Stopping..." << std::endl;
        light->stop();
    }
}

void get_params(int argc, char** argv, ldpi::Params& params)
{
    argparse::ArgumentParser program(argv[0]);

    program.add_argument("--config")
        .help("Config file to use")
        .default_value("config.json")
        .nargs(1);

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cout << program << std::endl;
        std::exit(1);
    }

    fs::path config_path = fs::path(program.get<std::string>("--config"));

    try {
        load_from_config(config_path, params);
        return; // return after successfully reading config
    } catch (const std::runtime_error& err) {
        std::cerr << "Error: " << err.what() << std::endl;
    }

    // act as finally block
    std::exit(1);
}

std::string modifier_flags_to_string(uint8_t flags)
{
    if (flags == ldpi::ModifierFlags::ALL)
    {
        return "[ALL]";
    }

    std::string flags_str = "[";

    static std::map<uint8_t, std::string> flags_map = {
        {ldpi::ModifierFlags::TCP_HANDSHAKE, "TCP Handshake"},
        {ldpi::ModifierFlags::HTTP_REQUEST, "HTTP"},
        {ldpi::ModifierFlags::TLS_CLIENT_HELLO, "HTTPS"},
        {ldpi::ModifierFlags::OTHER, "Other"}
    };

    for (auto& [key, value] : flags_map) {
        if (flags & key)
        {
            if (flags_str.size() > 1)
            {
                flags_str += ", ";
            }

            flags_str += flags_map[key];
        }
    }

    flags_str.append(1, ']');

    return flags_str;
}

void print_info(const ldpi::Params& params)
{
    std::cout << "LightDPI v" LDPI_VERSION << std::endl;

    if (!params.dns.empty())
    {
        std::cout << "\nDNS Configuration:" << std::endl;

        for (auto dns : params.dns)
        {
            std::cout << "- ";

            if (auto doh = dynamic_cast<ldpi::DNSOverHTTPS*>(dns))
            {
                std::cout << "DNS-over-HTTPS: " << doh->get_url();

                if (!doh->get_front().empty())
                {
                    std::cout << " (front: " << doh->get_front() << ")";
                }

                if (!doh->get_ip().empty())
                {
                    std::cout << " -> " << doh->get_ip();
                }
            }
            else
            {
                std::cout << "Unknown";
            }

            std::cout << std::endl;
        }
    }

    if (!params.modifiers.empty())
    {
        std::cout << "\nModifiers: " << std::endl;

        static std::unordered_map<ldpi::FakeModifier::Type, std::string> fake_str = {
            {ldpi::FakeModifier::Type::FAKE_RANDOM, "FAKE_RANDOM"},
            {ldpi::FakeModifier::Type::FAKE_DECOY, "FAKE_DECOY"}
        };

        for (ldpi::Modifier* modifier : params.modifiers)
        {
            std::string flags_str = modifier_flags_to_string(modifier->get_flags());
            std::cout << "- ";

            if (auto fake_modifier = dynamic_cast<ldpi::FakeModifier*>(modifier))
            {
                if (auto fakeack = dynamic_cast<ldpi::FakeACKModifier*>(modifier))
                {
                    std::cout << "FakeACK " << flags_str << std::endl;
                }
                else if (auto fakettl = dynamic_cast<ldpi::FakeTTLModifier*>(modifier))
                {
                    std::cout << "FakeTTL " << flags_str << std::endl;
                    std::cout << "  | Fake Packet TTL: " << fakettl->get_fake_packet_ttl() << std::endl;
                }
                else if (auto fakechecksum = dynamic_cast<ldpi::FakeChecksumModifier*>(modifier))
                {
                    std::cout << "FakeChecksum " << flags_str << std::endl;
                }

                std::cout << "  | Fake Packet Type: " << fake_str[fake_modifier->get_fake_packet_type()] << std::endl;
            }
            else
            {
                std::cout << "Unknown" << std::endl;
            }
        }
    }

    std::cout << "\nClick [CTRL+C] to stop" << std::endl;
}

// I would use WinMain but meh
int main(int argc, char** argv)
{
    ldpi::Params params;
    get_params(argc, argv, params);

    print_info(params);

    if (signal(SIGINT, handle_sigint) == SIG_ERR)
    {
        std::cout << "Warning: setting SIGINT handler was unsuccessfull" << std::endl;
    }

    light = new ldpi::LightDPI(params);

    try {
        light->start();
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << "Error code: " << GetLastError() << std::endl;
        return -1;
    }

    return 0;
}