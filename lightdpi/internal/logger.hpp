#pragma once

#include <string>
#include <cstring>
#include <cstdio>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

namespace ldpi::internal
{
    template <int t_size = 512>
    class Logger
    {
        // Compile-time logger that will be disabled in Release builds
    public:
        constexpr Logger()
        {
            memset(this->logbuf, 0, t_size);
            this->logbuf_ptr = &this->logbuf[0];
        };

        constexpr Logger& operator()(const std::string& str)
        {
            #ifdef LDPI_DEBUG
            memcpy(logbuf_ptr, str.c_str(), str.size());
            logbuf_ptr += str.size();
            #endif

            return *this;
        }

        constexpr Logger& operator()(const char* msg)
        {
            #ifdef LDPI_DEBUG
            auto len = strlen(msg);
            memcpy(logbuf_ptr, msg, len);
            logbuf_ptr += len;
            #endif

            return *this;
        }

        constexpr Logger& operator()(char* msg)
        {
            #ifdef LDPI_DEBUG
            return operator()(static_cast<const char*>(msg));
            #else
            return *this;
            #endif
        }

        constexpr Logger& operator()(int i)
        {
            #ifdef LDPI_DEBUG
            auto len = snprintf(logbuf_ptr, t_size - ((uintptr_t)logbuf_ptr - (uintptr_t)&logbuf[0]), "%d", i);
            logbuf_ptr += len;
            #endif

            return *this;
        }

        template <typename T, typename... Args>
        constexpr Logger& operator()(T v, Args... args)
        {
            operator()(v);
            return operator()(args...);
        }

        constexpr Logger& dummy()
        {
            return *this;
        }

        void commit()
        {
            #ifdef LDPI_DEBUG

            printf("%s\n", this->logbuf);
            memset(this->logbuf, 0, t_size);
            logbuf_ptr = &this->logbuf[0];

            #endif // LDPI_DEBUG
        }

    private:
        char logbuf[t_size];
        char* logbuf_ptr;
    };

    #ifdef LDPI_DEBUG
        #define withfl(...) operator()("[", __FILENAME__, ":", __LINE__, "] ").operator()(__VA_ARGS__)
    #else
        #define withfl(...) dummy()
    #endif
}