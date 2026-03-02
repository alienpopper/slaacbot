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

    /* Pointer to the LanConfig currently being populated (if any). */
    LanConfig *cur_lan = nullptr;

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

            /*
             * Every [lan] / [lan.X] section creates a new LanConfig.
             * Accepted forms: [lan], [lan.0], [lan.eth1], [lan.office], …
             */
            if (section == "lan" || section.rfind("lan.", 0) == 0) {
                cfg.lans.emplace_back();
                cur_lan = &cfg.lans.back();
            } else {
                cur_lan = nullptr;
            }
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
        } else if (cur_lan) {
            if (key == "interface")          cur_lan->interface = val;
            else if (key == "subnet_index") cur_lan->subnet_index = std::stoi(val);
        } else if (section == "dhcpv6") {
            if (key == "prefix_length")       cfg.prefix_length = std::stoi(val);
            else if (key == "iaid")           cfg.iaid = static_cast<uint32_t>(std::stoul(val));
            else if (key == "retransmit_timeout") cfg.retransmit_timeout = std::stoi(val);
            else if (key == "max_retransmit") cfg.max_retransmit = std::stoi(val);
        } else if (section == "ra") {
            if (key == "interval")            cfg.ra_interval = std::stoi(val);
            else if (key == "router_lifetime") cfg.router_lifetime = std::stoi(val);
            else if (key == "mtu")            cfg.mtu = std::stoi(val);
            else if (key == "hop_limit")      cfg.hop_limit = std::stoi(val);
        }
    }

    /* Validate mandatory fields */
    if (cfg.wan_interface.empty())
        throw std::runtime_error("config: wan/interface is required");
    if (cfg.lans.empty())
        throw std::runtime_error("config: at least one [lan] section is required");
    for (size_t i = 0; i < cfg.lans.size(); ++i) {
        if (cfg.lans[i].interface.empty())
            throw std::runtime_error(
                "config: lan[" + std::to_string(i) + "]/interface is required");
    }

    LOG_INF("Config loaded: WAN=%s  %zu LAN interface(s)  prefix_len=/%d",
            cfg.wan_interface.c_str(), cfg.lans.size(), cfg.prefix_length);
    for (size_t i = 0; i < cfg.lans.size(); ++i) {
        LOG_INF("  LAN[%zu]: %s  subnet_index=%d",
                i, cfg.lans[i].interface.c_str(), cfg.lans[i].subnet_index);
    }
    return cfg;
}
