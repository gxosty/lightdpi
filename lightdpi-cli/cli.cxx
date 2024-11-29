#include <iostream>
#include <signal.h>
#include <argparse/argparse.hpp>
#include <lightdpi/lightdpi.hpp>

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
    // argparse::ArgumentParser program(argv[0]);

    // program.add_argument("--dns");
}

void print_info(const ldpi::Params& params)
{
    std::cout << "LightDPI v" LDPI_VERSION << std::endl;
}

int main()
{

}

// I would use WinMain but meh
int _main(int argc, char** argv)
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