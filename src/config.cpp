/*
 * config.cpp - Simple INI-file parser that populates a Config struct.
 */
#include "config.h"
#include "log.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

/* ---- helpers ---------------------------------------------------------- */

static std::string trim(const std::string &s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

/* ---- public API ------------------------------------------------------- */

Config load_config(const std::string &path) {
    std::ifstream in(path);
    if (!in.is_open())
        throw std::runtime_error("Cannot open config file: " + path);

    Config cfg;
    std::string section;
    std::string line;
    int lineno = 0;

    while (std::getline(in, line)) {
        ++lineno;
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;

        /* Section header */
        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.size() - 2);
            std::transform(section.begin(), section.end(), section.begin(),
                           ::tolower);
            continue;
        }

        /* key = value */
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            LOG_WRN("config:%d: ignoring malformed line", lineno);
            continue;
        }
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);

        /* Map into Config fields */
        if (section == "wan") {
            if (key == "interface") cfg.wan_interface = val;
        } else if (section == "lan") {
            if (key == "interface")    cfg.lan_interface = val;
            else if (key == "subnet_index") cfg.subnet_index = std::stoi(val);
        } else if (section == "dhcpv6") {
            if (key == "prefix_length")       cfg.prefix_length = std::stoi(val);
            else if (key == "iaid")           cfg.iaid = static_cast<uint32_t>(std::stoul(val));
            else if (key == "retransmit_timeout") cfg.retransmit_timeout = std::stoi(val);
            else if (key == "max_retransmit") cfg.max_retransmit = std::stoi(val);
        } else if (section == "ra") {
            if (key == "interval")            cfg.ra_interval = std::stoi(val);
            else if (key == "router_lifetime") cfg.router_lifetime = std::stoi(val);
            else if (key == "valid_lifetime")  cfg.valid_lifetime = std::stoi(val);
            else if (key == "preferred_lifetime") cfg.preferred_lifetime = std::stoi(val);
            else if (key == "mtu")            cfg.mtu = std::stoi(val);
            else if (key == "hop_limit")      cfg.hop_limit = std::stoi(val);
        }
    }

    /* Validate mandatory fields */
    if (cfg.wan_interface.empty())
        throw std::runtime_error("config: wan/interface is required");
    if (cfg.lan_interface.empty())
        throw std::runtime_error("config: lan/interface is required");

    LOG_INF("Config loaded: WAN=%s  LAN=%s  prefix_len=/%d  subnet=%d",
            cfg.wan_interface.c_str(), cfg.lan_interface.c_str(),
            cfg.prefix_length, cfg.subnet_index);
    return cfg;
}
