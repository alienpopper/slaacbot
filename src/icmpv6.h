/*
 * icmpv6.h - Router Advertisement sender / Router Solicitation listener.
 *
 * Builds ICMPv6 Router Advertisement packets by hand and sends them
 * on the LAN interface.  Listens for Router Solicitations from clients
 * so it can respond immediately.
 */
#pragma once

#include "config.h"

#include <chrono>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <vector>

class RAServer {
public:
    /**
     * @param iface  LAN interface name
     * @param cfg    Parsed configuration (RA parameters)
     */
    RAServer(const std::string &iface, const Config &cfg);
    ~RAServer();

    RAServer(const RAServer &)            = delete;
    RAServer &operator=(const RAServer &) = delete;

    /**
     * Set (or update) the prefix advertised in RAs.
     */
    void set_prefix(const struct in6_addr &prefix, int prefix_len,
                    uint32_t valid_lt, uint32_t preferred_lt);

    /**
     * Send an unsolicited Router Advertisement to ff02::1 (all-nodes).
     */
    void send_ra();

    /**
     * Send an RA that deprecates a prefix (lifetimes = 0).
     * Used when the ISP changes the delegated prefix.
     */
    void send_deprecation(const struct in6_addr &old_prefix, int prefix_len);

    /**
     * Read and handle a Router Solicitation from the socket.
     * Responds with an RA to the solicitor (or all-nodes).
     */
    bool handle_rs();

    /** Raw socket fd, for use with poll(). */
    int fd() const { return sock_; }

private:
    int         sock_ = -1;
    std::string iface_;
    int         if_index_;
    uint8_t     mac_[6]{};

    /* Rate-limiting: RFC 4861 §6.2.6 minimum delay between RAs */
    std::chrono::steady_clock::time_point last_ra_time_{};
    static constexpr int MIN_RA_DELAY_S = 3;

    /* Current prefix being advertised */
    struct in6_addr prefix_{};
    int             prefix_len_     = 0;
    uint32_t        valid_lt_       = 0;
    uint32_t        preferred_lt_   = 0;

    /* RA parameters from config */
    int      router_lifetime_;
    int      hop_limit_;
    int      mtu_;

    /* Build an RA packet (ICMPv6 payload only; kernel adds IPv6 header). */
    std::vector<uint8_t> build_ra(const struct in6_addr &pfx, int pfx_len,
                                   uint32_t valid_lt, uint32_t pref_lt);

    void send_raw(const std::vector<uint8_t> &pkt,
                  const struct sockaddr_in6 &dest);
};
