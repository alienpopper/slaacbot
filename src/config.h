/*
 * config.h - Configuration file parser for slaacbot.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

/* Per-LAN-interface configuration. */
struct LanConfig {
    std::string interface;               /* e.g. "eth1" */
    int         subnet_index = 0;        /* Which /64 inside the delegated prefix */
};

struct Config {
    /* WAN (upstream / ISP-facing) */
    std::string wan_interface;

    /* LAN (downstream / client-facing) – one or more */
    std::vector<LanConfig> lans;

    /* DHCPv6-PD */
    int         prefix_length    = 56;   /* Requested prefix length */
    uint32_t    iaid             = 1;
    int         retransmit_timeout = 5;  /* Seconds */
    int         max_retransmit   = 10;

    /* Router Advertisements (shared by all LAN interfaces) */
    int         ra_interval      = 30;   /* Seconds between unsolicited RAs */
    int         router_lifetime  = 1800;
    int         valid_lifetime   = 86400;
    int         preferred_lifetime = 14400;
    int         mtu              = 0;    /* 0 = omit MTU option */
    int         hop_limit        = 64;
};

Config load_config(const std::string &path);
