#include "WGRelay.hpp"
#include <borealis.hpp>
#include <string>
#include <cstdlib>
#include <arpa/inet.h>
#include <sys/socket.h>

namespace {
std::string strip_ipv4_port(const std::string& address) {
    const auto firstColon = address.find(':');
    if (firstColon == std::string::npos) {
        return address;
    }
    if (address.find(':', firstColon + 1) != std::string::npos) {
        return address;
    }
    return address.substr(0, firstColon);
}

std::string ipv4_port(const std::string& address) {
    const auto firstColon = address.find(':');
    if (firstColon == std::string::npos) {
        return "";
    }
    if (address.find(':', firstColon + 1) != std::string::npos) {
        return "";
    }
    return address.substr(firstColon + 1);
}
}

WGRelay::~WGRelay() {
    close();
}

int WGRelay::set(const Host& host) {
    if (host.wg_enable) {
        std::string new_target = host.real_address();
        if (enabled) {
            if (target == new_target && std::memcmp(&config, &host.wg_config, sizeof(WgConfig)) == 0) {
                return 1;
            } else {
                close();
            }
        }

        target = new_target;
        char tunnel_ip[INET_ADDRSTRLEN];
        std::string target_ip = strip_ipv4_port(target);
        std::string target_port_s = ipv4_port(target);
        uint16_t target_port = target_port_s.empty() ? 47989 : (uint16_t) std::strtoul(target_port_s.c_str(), nullptr, 10);
        if (inet_ntop(AF_INET, &host.wg_config.tunnel_ip, tunnel_ip, INET_ADDRSTRLEN) &&
            (tun = wg_init(&(config = host.wg_config))) &&
            (wg_connect(tun) == WG_OK) &&
            (wg_start(tun) == WG_OK) &&
            (relay = new wgnx::LwipRelay (tun, rconfig)) &&
            relay->start(tunnel_ip, target_ip) &&
            relay->startTcpRelay(target_port - 5, target_port - 5) &&
            relay->startTcpRelay(target_port, target_port) &&
            relay->startTcpRelay(target_port + 21, target_port + 21) &&
            relay->startUdpRelay(target_port + 9, target_port + 9) &&
            relay->startUdpRelay(target_port + 10, target_port + 10) &&
            relay->startUdpRelay(target_port + 11, target_port + 11) &&
            relay->startUdpRelay(target_port + 13, target_port + 13) &&
            relay->startUdpRelay(target_port + 21, target_port + 21)
        ) {
            enabled = true;
            return 1;
        } else {
            return 0;
        }
    } else if (enabled) {
        close();
    }
    return -1;
}

void WGRelay::close() {
    enabled = false;
    delete relay;
    relay = nullptr;
    wg_close(tun);
    tun = nullptr;
}
