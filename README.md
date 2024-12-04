# LightDPI: A C++ DPI Circumvention Tool (Alpha/Pre-release)

LightDPI is a command-line application written in C++ designed to circumvent Deep Packet Inspection (DPI) techniques used by firewalls and network monitors. It is currently under development (Alpha/Pre-release) and offers various techniques to achieve this goal.

> [!CAUTION]
> LightDPI is provided as is, and mainly for educational purposes. Using it to bypass security measures without authorization is at your own risk.

> [!IMPORTANT]
> LightDPI is Windows only!

### Features:

* **Command-Line Interface:** Simple to use with a single optional argument.
* **Configurable:** Modifies behavior through a JSON configuration file.
* **Zero Attack Modifier:** Desynchronizes DPI by altering initial TCP SYN packets. (Implemented)
* **HTTPS First Attack Modifier:** Modifies packets destined to port 443 (e.g., Fake Packets). (Implemented)
* **Expandable:** Designed to incorporate additional modifiers in the future. (Planned)

### Usage:

LightDPI requires a configuration file (default: `config.json`) to define its behavior. You can launch it with the following command:

```
./LightDPI [--config <config_file>]
```

**Arguments:**

* `--config`: (Optional) Path to the configuration file. Defaults to `config.json`.

### Configuration File:

The configuration file is a JSON file that defines the parameters LightDPI uses. Currently, it supports:

* `dns`: List of DNS resolution methods to use. (default: `null`)
* `modifiers`: List of Modifiers for altering TCP Handshake, HTTP, HTTPS and other packets.
* (Future) Additional options and paramters can be defined here.

**Example configuration file:**
```json
{
  "dns" : [
    {
      "type" : "doh", // DNS-over-HTTPS with Domain Fronting support
      "params" : {
        "url" : "https://forbidden-doh.example.com/dns-query",
        "ip" : "66.152.254.38", // optional
        "front" : "allowed-doh.example.com" // optional
      }
    }
  ],

  "modifiers" : [
    {
      "type" : "fake-ttl", // Fake Packets with Invalid TTL
      "params" : {
        "fake-packet-type" : "fake-decoy",
        "fake-packet-ttl" : 7
      }
    }
  ]
}
```
> [!NOTE]
> Note that comments in json are not allowed, they are here only for explanation purposes

**Currently supported modifiers:**
* `fake-ack` (http, https). Sends fake packet with invalid TCP ACK number.
* `fake-ttl` (http, https). Sends fake packet with invalid IP TTL number. Params:
  * `fake-packet-ttl`: TTL of fake packet. Must be number.
* `fake-checksum` (http, https). Sends fake packet with invalid TCP Checksum.
> [!NOTE]
> Modifiers that start with `fake-` prefix have required parameter `fake-packet-type`, which is type of fake packet to send. Can be `FAKE_DECOY` (sends fake HTTP request or TLSClientHello packet depending on protocol) or `FAKE_RANDOM` (sends random bytes in body/payload).

### Building:

LightDPI uses CMake for building the project.

```cmd
git clone https://github.com/gxosty/lightdpi
cd lightdpi
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --parallel 4
```

### License:

LightDPI is licensed under the [GPL-3.0 license](LICENSE). See the LICENSE file for details.

Third-party libraries used in this project may have different licenses. Please refer to the respective library documentation for details.

### Dependencies

LightDPI utilizes the following third-party libraries:

* [**WinDivert:**](https://github.com/basil00/WinDivert) Network packet capturing library
* [**Nlohmann JSON:**](https://github.com/nlohmann/json) JSON parsing and serialization library (https://json.nlohmann.me/)
* [**libcurl:**](https://github.com/curl/curl) Easy-to-use URL transfer library (https://curl.se/)
* [**WolfSSL:**](https://github.com/wolfSSL/wolfssl) Embedded SSL/TLS library (https://wolfssl.com/)
* [**zlib:**](https://github.com/madler/zlib) Data compression library (https://www.zlib.org/)
* [**base64:**](https://github.com/tobiaslocker/base64) Base64 encoding/decoding library
* [**argparse:**](https://github.com/p-ranav/argparse) Command-line parsing library

### Current Status:

This is an Alpha/Pre-release version. Functionality is limited and may be buggy.

### Future Development:

* Implement additional attack modifiers.
* Enhance configuration options.
* Improve error handling and logging.
