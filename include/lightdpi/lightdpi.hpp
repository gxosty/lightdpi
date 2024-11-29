#pragma once

#include "exceptions.hpp"
#include "params.hpp"
#include "common/windivertwrapper.hpp"

#include <string>

namespace ldpi
{
    class LightDPI
    {
    public:
        // Constructor takes ownership of Params
        LightDPI(const Params& params);
        ~LightDPI();

        void start();
        void stop();

    private:
        HANDLE _handle;
        Params _params;
        bool _running;

    private:
        void _get_filter(std::string& filter);
    };
}