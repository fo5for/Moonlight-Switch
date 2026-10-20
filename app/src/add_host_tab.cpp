//
//  add_host_tab.cpp
//  Moonlight
//
//  Created by XITRIX on 26.05.2021.
//

#include "add_host_tab.hpp"
#include "DiscoverManager.hpp"
#include "helper.hpp"
#include "main_tabs_view.hpp"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#if defined(PLATFORM_IOS) || defined(PLATFORM_TVOS) || defined(PLATFORM_VISIONOS)
extern void darwin_mdns_start(ServerCallback<std::vector<Host>>& callback);
extern void darwin_mdns_stop();
#endif

#ifdef __SWITCH__
#include "WGRelay.hpp"
#endif

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

bool is_private_ipv4(const in_addr& address) {
    const uint32_t value = ntohl(address.s_addr);
    const uint8_t a = (value >> 24) & 0xFF;
    const uint8_t b = (value >> 16) & 0xFF;

    return a == 10 || a == 127 || (a == 169 && b == 254) ||
           (a == 192 && b == 168) || (a == 172 && b >= 16 && b <= 31);
}

bool should_store_manual_address_as_remote(const std::string& address) {
    const auto hostPart = strip_ipv4_port(address);
    if (hostPart.empty()) {
        return false;
    }

    in_addr parsed{};
    if (inet_pton(AF_INET, hostPart.c_str(), &parsed) != 1) {
        return false;
    }

    return !is_private_ipv4(parsed);
}
}

AddHostTab::AddHostTab() {
    // Inflate the tab from the XML file
    this->inflateFromXMLRes("xml/tabs/add_host.xml");

    hostIP->init("add_host/host_ip"_i18n, "");
    hostIP->setPlaceholder("192.168.1.109:47989");
    hostIP->setHint("192.168.1.109:47989");

#ifdef __SWITCH__
    wg_enable->init("add_host/wireguard/enable"_i18n, false, [this](bool enable) {
        const auto visibility = enable ? brls::Visibility::VISIBLE : brls::Visibility::GONE;
        wg_header->setVisibility(visibility);
        private_key->setVisibility(visibility);
        gen_key->setVisibility(visibility);
        tunnel_ip->setVisibility(visibility);
        peer_public_key->setVisibility(visibility);
        endpoint->setVisibility(visibility);
        keepalive_interval->setVisibility(visibility);
        mtu->setVisibility(visibility);
        preshared_key->setVisibility(visibility);
    });
    private_key->init("add_host/wireguard/private_key"_i18n, "", [](std::string){}, "", "", WG_KEY_BASE64_LEN - 1);
    gen_key->setText("add_host/wireguard/gen_key"_i18n);
    gen_key->registerClickAction([this](View* view) {
        uint8_t priv[WG_KEY_LEN];
        uint8_t pub[WG_KEY_LEN];
        char priv_base64[WG_KEY_BASE64_LEN];
        char pub_base64[WG_KEY_BASE64_LEN];
        wg_generate_keypair(priv, pub);
        if (!wg_key_to_base64(priv_base64, WG_KEY_BASE64_LEN, priv) &&
            !wg_key_to_base64(pub_base64, WG_KEY_BASE64_LEN, pub)
        ) {
            private_key->setValue(priv_base64);
            showAlert("add_host/wireguard/private_key"_i18n + ": " + priv_base64 + "\n\n" +
                      "add_host/wireguard/public_key"_i18n + ": " + pub_base64);
        }
        return true;
    });
    tunnel_ip->init("add_host/wireguard/tunnel_ip"_i18n, "", [](std::string){}, "192.168.1.110", "", INET_ADDRSTRLEN - 1);
    peer_public_key->init("add_host/wireguard/peer_public_key"_i18n, "", [](std::string){}, "", "", WG_KEY_BASE64_LEN - 1);
    endpoint->init("add_host/wireguard/endpoint"_i18n, "", [](std::string){}, "vpn.example.net:51820", "", WG_MAX_ENDPOINT - 1);
    keepalive_interval->init("add_host/wireguard/keepalive_interval"_i18n, 0, [](long){}, "", 5);
    mtu->init("add_host/wireguard/mtu"_i18n, 0, [](long){}, "", 5);
    preshared_key->init("add_host/wireguard/preshared_key"_i18n, "", [](std::string){}, "", "", WG_KEY_BASE64_LEN - 1);
    wg_enable->getEvent()->fire(false);
#else
    wg_enable->removeFromSuperView(true);
    wg_header->removeFromSuperView(true);
    private_key->removeFromSuperView(true);
    gen_key->removeFromSuperView(true);
    tunnel_ip->removeFromSuperView(true);
    peer_public_key->removeFromSuperView(true);
    endpoint->removeFromSuperView(true);
    keepalive_interval->removeFromSuperView(true);
    mtu->removeFromSuperView(true);
    preshared_key->removeFromSuperView(true);
#endif

    connect->setText("add_host/connect"_i18n);
    connect->registerClickAction([this](View* view) {
        Host host;
        const auto inputAddress = hostIP->getValue();
        if (should_store_manual_address_as_remote(inputAddress)) {
            host.remoteAddress = inputAddress;
        } else {
            host.address = inputAddress;
        }
#ifdef __SWITCH__
        if (host.wg_enable = wg_enable->isOn()) {
            if (wg_key_from_base64(host.wg_config.private_key, private_key->getValue().c_str())) {
                showError("add_host/wireguard/private_key_error"_i18n);
                return true;
            }
            if (inet_pton(AF_INET, tunnel_ip->getValue().c_str(), &host.wg_config.tunnel_ip) != 1) {
                showError("add_host/wireguard/tunnel_ip_error"_i18n);
                return true;
            }
            if (wg_key_from_base64(host.wg_config.peer_public_key, peer_public_key->getValue().c_str())) {
                showError("add_host/wireguard/peer_public_key_error"_i18n);
                return true;
            }
            std::string ep = endpoint->getValue();
            std::string ep_host = strip_ipv4_port(ep);
            std::strncpy(host.wg_config.endpoint_host, ep_host.c_str(), WG_MAX_ENDPOINT);
            std::string ep_port = ipv4_port(ep);
            host.wg_config.endpoint_port = ep_port.empty() ? 51820 : (uint16_t) std::strtoul(ep_port.c_str(), nullptr, 10);
            host.wg_config.keepalive_interval = keepalive_interval->getValue();
            host.wg_config.mtu = mtu->getValue();
            std::string psk = preshared_key->getValue();
            if (host.wg_config.has_preshared_key = !psk.empty()) {
                if (wg_key_from_base64(host.wg_config.preshared_key, psk.c_str())) {
                    showError("add_host/wireguard/preshared_key_error"_i18n);
                    return true;
                }
            }
        }
#endif
        connectHost(host);
        return true;
    });

    if (GameStreamClient::can_find_host())
        findHost();
    else {
        searchHeader->setTitle("add_host/search_error"_i18n);
        loader->setVisibility(brls::Visibility::GONE);
    }

    registerAction("add_host/search_refresh"_i18n, ControllerButton::BUTTON_X,
                   [this](View* view) {
#ifdef MULTICAST_DISABLED
                       DiscoverManager::instance().reset();
#endif
                       findHost();
                       return true;
                   });
    setActionAvailable(BUTTON_X, GameStreamClient::can_find_host());
}

void AddHostTab::fillSearchBox(const GSResult<std::vector<Host>>& hostsRes) {
    loader->setVisibility(DiscoverManager::instance().isPaused()
                              ? brls::Visibility::GONE
                              : brls::Visibility::VISIBLE);

    if (hostsRes.isSuccess()) {
        appendSearchHosts(hostsRes.value());
    } else {
        loader->setVisibility(brls::Visibility::GONE);
        searchHeader->setTitle("add_host/search"_i18n + " - " +
                               hostsRes.error());
    }
}

void AddHostTab::appendSearchHosts(const std::vector<Host>& hosts) {
    for (const Host& host : hosts) {
        const auto displayAddress = host.real_address();
        if (displayAddress.empty() || searchBoxIpExists(displayAddress))
            continue;

        auto hostButton = new brls::DetailCell();
        hostButton->setText(host.hostname);
        hostButton->setDetailText(displayAddress);
        hostButton->setDetailTextColor(
            brls::Application::getTheme()["brls/text_disabled"]);
        hostButton->registerClickAction([this, host](View* view) {
            connectHost(host);
            return true;
        });
        searchBox->addView(hostButton);
    }
}

bool AddHostTab::searchBoxIpExists(const std::string& ip) {
    return std::any_of(searchBox->getChildren().begin(), searchBox->getChildren().end(), [ip](View* child) {
        auto cell = dynamic_cast<DetailCell*>(child);
        return cell->detail->getFullText() == ip;
    });
}

void AddHostTab::findHost() {
#ifdef MULTICAST_DISABLED
    DiscoverManager::instance().start();
    fillSearchBox(DiscoverManager::instance().getHosts());
    DiscoverManager::instance().getHostsUpdateEvent()->unsubscribe(
        searchSubscription);
    searchSubscription =
        DiscoverManager::instance().getHostsUpdateEvent()->subscribe(
            [this](auto result) { fillSearchBox(result); });
#else
    stopSearchHost();
    const uint64_t generation = searchGeneration;
    searchBox->clearViews();
    searchHeader->setTitle("add_host/search"_i18n);
    loader->setVisibility(brls::Visibility::VISIBLE);
    ASYNC_RETAIN
#if defined(PLATFORM_IOS) || defined(PLATFORM_TVOS) || defined(PLATFORM_VISIONOS)
    darwin_mdns_start(
#else
    GameStreamClient::find_hosts(
#endif
        [ASYNC_TOKEN, generation](const GSResult<std::vector<Host>>& result) {
            ASYNC_RELEASE

            if (generation != searchGeneration) {
                return;
            }

            if (result.isSuccess()) {
                appendSearchHosts(result.value());
            } else {
                loader->setVisibility(brls::Visibility::GONE);
                showError(result.error(), [] {});
            }
        });
#endif
}

void AddHostTab::stopSearchHost() {
    searchGeneration++;
#ifdef MULTICAST_DISABLED
    DiscoverManager::instance().pause();
#elif defined(PLATFORM_IOS)
#elif defined(PLATFORM_TVOS) || defined(PLATFORM_VISIONOS)
#else
    GameStreamClient::cancel_find_hosts();
#endif
}

void AddHostTab::connectHost(const Host& host) {
    pauseSearching();

    Dialog* loaderView = createLoadingDialog("add_host/try_connect"_i18n);
    loaderView->open();

    GameStreamClient::instance().connect(
        host, [this, loaderView, host](const GSResult<SERVER_DATA>& result) {
            loaderView->close([this, result, host] {
                if (result.isSuccess()) {
                    Host pairedHost = host;
                    pairedHost.hostname = result.value().hostname;
                    pairedHost.mac = result.value().mac;

                    if (result.value().paired) {
                        showAlert("add_host/paired_error"_i18n, [pairedHost] {
                            Settings::instance().add_host(pairedHost);
                            MainTabs::getInstanse()->refillTabs();
                        });

                        return;
                    }

                    auto pin = fmt::format("{}{}{}{}", (int)rand() % 10, (int)rand() % 10,
                            (int)rand() % 10, (int)rand() % 10);

                    brls::Dialog* dialog = createLoadingDialog(
                        "add_host/pair_prefix"_i18n + pin +
                        "add_host/pair_postfix"_i18n);
                    dialog->setCancelable(false);
                    dialog->open();

                    ASYNC_RETAIN
                    GameStreamClient::instance().pair(
                        pairedHost, pin,
                        [ASYNC_TOKEN, pairedHost, dialog](const GSResult<bool>& result) {
                            ASYNC_RELEASE
                            dialog->dismiss([result, pairedHost] {
                                if (result.isSuccess()) {
                                    Settings::instance().add_host(pairedHost);
                                    MainTabs::getInstanse()->refillTabs();
                                    AddHostTab::startSearching();
                                } else {
                                    showError(result.error(), [] {
                                        AddHostTab::startSearching();
                                    });
                                }
                            });
                        });
                } else {
                    showError(result.error(),
                              [] { AddHostTab::startSearching(); });
                }
            });
        });
}

void AddHostTab::pauseSearching() {
#ifdef MULTICAST_DISABLED
    DiscoverManager::instance().pause();
#endif
}

void AddHostTab::startSearching() {
#ifdef MULTICAST_DISABLED
    DiscoverManager::instance().start();
#endif
}

AddHostTab::~AddHostTab() {
    stopSearchHost();
#ifdef MULTICAST_DISABLED
    DiscoverManager::instance().pause();
    DiscoverManager::instance().getHostsUpdateEvent()->unsubscribe(
        searchSubscription);
#elif defined(PLATFORM_IOS) || defined(PLATFORM_TVOS) || defined(PLATFORM_VISIONOS)
    darwin_mdns_stop();
#endif
}

brls::View* AddHostTab::create() {
    // Called by the XML engine to create a new AddHostTab
    return new AddHostTab();
}
