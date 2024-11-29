#include <lightdpi/lightdpi.hpp>

namespace ldpi
{
    LightDPI::LightDPI(const Params& params)
        : _params(std::move(params)),
          _running{false},
          _handle{nullptr} {}

    LightDPI::~LightDPI()
    {
        if (_handle)
        {
            WinDivertClose(_handle);
            _handle = nullptr;
        }
    }

    void LightDPI::start()
    {
        HANDLE handle = WinDivertOpen(
            "ip.DstAddr == 209.85.233.147",
            WINDIVERT_LAYER_NETWORK,
            WINDIVERT_PRIORITY_HIGHEST-1000,
            0
        );

        if (handle == INVALID_HANDLE_VALUE)
        {
            throw WinDivertOpenError("Failed opening WinDivert handle");
        }

        WinDivertWrapper _divert(handle);

        Packet packet;
        WinDivertAddress address;
        _running = true;

        while (_running)
        {
            if (_divert.recv(&packet, &address))
            {
                _divert.send(packet, &address);
            }
            else
            {

            }
        }
    }

    void LightDPI::stop()
    {
        _running = false;
    }

    void _get_filter(std::string& filter)
    {

    }
}