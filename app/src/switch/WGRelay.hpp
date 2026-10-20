#pragma once

#include "Singleton.hpp"
#include "Settings.hpp"
#include "wg_lwip_relay.hpp"
#include <borealis.hpp>
#include <string>

struct Host;
constexpr size_t WG_KEY_BASE64_LEN = WG_KEY_LEN * 8 / 6 + 3;

class WGRelay : public Singleton<WGRelay> {
  public:
    ~WGRelay();

    int set(const Host& host);
    void close();

  private:
    WgTunnel* tun = nullptr;
    wgnx::LwipRelay* relay = nullptr;

    bool enabled = false;
    std::string target;
    WgConfig config = {};
    wgnx::LwipRelayConfig rconfig = {
        [](wgnx::LogLevel level, const char* message) {
            switch (level) {
                case wgnx::LogLevel::Debug:
                    brls::Logger::debug("{}", message);
                    break;
                case wgnx::LogLevel::Info:
                    brls::Logger::info("{}", message);
                    break;
                case wgnx::LogLevel::Error:
                    brls::Logger::error("{}", message);
                    break;
            }
        },
        {},
        true
    };
};
