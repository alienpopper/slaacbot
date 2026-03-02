/*
 * main.cpp - slaacbot daemon entry point.
 *
 * Orchestrates the entire lifecycle:
 *
 *  1. Parse configuration
 *  2. Prepare interfaces (forwarding, accept_ra)
 *  3. Obtain a delegated prefix from the ISP via DHCPv6-PD
 *  4. Carve a /64, assign it to the LAN interface, add routes
 *  5. Start sending Router Advertisements (SLAAC) on the LAN
 *  6. Event loop: periodic RAs, respond to RS, handle DHCPv6 renewals
 *  7. On prefix change: tear down old config, apply new, notify clients
 *  8. On shutdown: deprecate prefix, release DHCPv6 lease, clean up
 */
#include "config.h"
#include "dhcpv6.h"
#include "icmpv6.h"
#include "log.h"
#include "netconfig.h"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

/* ---- Globals --------------------------------------------------------- */

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int) { g_running = 0; }

/* ---- State ----------------------------------------------------------- */

struct LanState {
    struct in6_addr subnet{};      /* /64 carved from delegated prefix   */
    struct in6_addr host_addr{};   /* ::1 inside the subnet              */
    int             prefix_len = 64;
    bool            configured = false;
};

/* ---- Apply / tear down LAN configuration ----------------------------- */

static void apply_lan(const Config &cfg, LanState &lan,
                      const DelegatedPrefix &dp, RAServer &ra) {
    /* Carve subnet #subnet_index as a /64 */
    lan.subnet = netconfig::carve_subnet(dp.prefix, dp.prefix_len,
                                         cfg.subnet_index, 64);
    lan.prefix_len = 64;

    /* Host address = subnet::1 */
    lan.host_addr = netconfig::make_host_addr(lan.subnet, 64, 1);

    LOG_INF("LAN config: %s/64  host %s",
            netconfig::to_string(lan.subnet).c_str(),
            netconfig::to_string(lan.host_addr).c_str());

    netconfig::add_address(cfg.lan_interface, lan.host_addr, 64);
    netconfig::add_route(lan.subnet, 64, cfg.lan_interface);
    lan.configured = true;

    /* Update the RA server with the new prefix */
    ra.set_prefix(lan.subnet, 64, dp.valid_lt, dp.preferred_lt);
    ra.send_ra();            /* Announce immediately */
}

static void teardown_lan(const Config &cfg, LanState &lan, RAServer &ra) {
    if (!lan.configured) return;
    LOG_INF("Tearing down LAN configuration");

    ra.send_deprecation(lan.subnet, 64);

    netconfig::del_route(lan.subnet, 64, cfg.lan_interface);
    netconfig::del_address(cfg.lan_interface, lan.host_addr, 64);
    lan.configured = false;
}

/* ---- Usage ----------------------------------------------------------- */

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [-c config] [-d] [-v]\n"
            "  -c FILE   Configuration file (default: /etc/slaacbot.conf)\n"
            "  -d        Daemonise (fork to background)\n"
            "  -v        Verbose (debug-level logging)\n",
            argv0);
}

/* ====================================================================== */
/*  main                                                                  */
/* ====================================================================== */

int main(int argc, char *argv[]) {
    std::string config_path = "/etc/slaacbot.conf";
    bool daemonise = false;

    int opt;
    while ((opt = getopt(argc, argv, "c:dvh")) != -1) {
        switch (opt) {
        case 'c': config_path = optarg; break;
        case 'd': daemonise = true;     break;
        case 'v': g_log_level = LOG_DEBUG; break;
        case 'h': /* fall through */
        default:  usage(argv[0]); return (opt == 'h') ? 0 : 1;
        }
    }

    /* ---- Load configuration ------------------------------------------ */
    Config cfg;
    try {
        cfg = load_config(config_path);
    } catch (const std::exception &e) {
        LOG_ERR("Config: %s", e.what());
        return 1;
    }

    /* ---- Seed RNG ---------------------------------------------------- */
    srandom(static_cast<unsigned>(time(nullptr) ^ getpid()));

    /* ---- Daemonise if requested -------------------------------------- */
    if (daemonise) {
        if (daemon(0, 0) < 0) {
            LOG_ERR("daemon(): %s", strerror(errno));
            return 1;
        }
    }

    /* ---- Signal handling --------------------------------------------- */
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    /* ---- Prepare interfaces ------------------------------------------ */
    try {
        netconfig::enable_forwarding();
        netconfig::set_accept_ra(cfg.wan_interface, 2);  /* Accept RA even when forwarding */
        netconfig::set_accept_ra(cfg.lan_interface, 0);  /* We ARE the router on LAN */
    } catch (const std::exception &e) {
        LOG_ERR("Interface setup: %s", e.what());
        return 1;
    }

    /* ---- Create DHCPv6 client ---------------------------------------- */
    uint8_t wan_mac[6];
    try {
        netconfig::get_mac(cfg.wan_interface, wan_mac);
    } catch (const std::exception &e) {
        LOG_ERR("%s", e.what());
        return 1;
    }

    std::unique_ptr<DHCPv6Client> dhcp;
    try {
        dhcp = std::make_unique<DHCPv6Client>(
            cfg.wan_interface, wan_mac, cfg.iaid, cfg.prefix_length,
            cfg.retransmit_timeout, cfg.max_retransmit);
    } catch (const std::exception &e) {
        LOG_ERR("DHCPv6 init: %s", e.what());
        return 1;
    }

    /* ---- Obtain initial prefix --------------------------------------- */
    while (g_running && !dhcp->obtain_prefix()) {
        LOG_WRN("DHCPv6: retrying in %d seconds …", cfg.retransmit_timeout);
        sleep(static_cast<unsigned>(cfg.retransmit_timeout));
    }
    if (!g_running) return 0;

    /* ---- Create RA server -------------------------------------------- */
    std::unique_ptr<RAServer> ra;
    try {
        ra = std::make_unique<RAServer>(cfg.lan_interface, cfg);
    } catch (const std::exception &e) {
        LOG_ERR("RA init: %s", e.what());
        return 1;
    }

    /* ---- Apply LAN configuration ------------------------------------- */
    LanState lan;
    try {
        apply_lan(cfg, lan, dhcp->prefix(), *ra);
    } catch (const std::exception &e) {
        LOG_ERR("LAN config: %s", e.what());
        return 1;
    }

    /* ---- Compute renewal timers -------------------------------------- */
    using clock = std::chrono::steady_clock;
    auto lease_start = clock::now();

    auto t1_secs =
        dhcp->prefix().t1 > 0 ? dhcp->prefix().t1 : dhcp->prefix().valid_lt / 2;
    auto t2_secs =
        dhcp->prefix().t2 > 0 ? dhcp->prefix().t2
                               : dhcp->prefix().valid_lt * 4 / 5;

    auto renew_time  = lease_start + std::chrono::seconds(t1_secs);
    auto rebind_time = lease_start + std::chrono::seconds(t2_secs);
    auto next_ra     = clock::now();

    bool renew_sent = false;
    bool rebind_sent = false;

    LOG_INF("Event loop starting  (T1=%us  T2=%us  RA every %ds)",
            t1_secs, t2_secs, cfg.ra_interval);

    /* ==== Main event loop ============================================ */

    struct pollfd fds[2];
    fds[0].fd     = dhcp->fd();
    fds[0].events = POLLIN;
    fds[1].fd     = ra->fd();
    fds[1].events = POLLIN;

    while (g_running) {
        auto now = clock::now();

        /* Calculate poll timeout: next event = min(next_ra, renew_time) */
        auto next_event = next_ra;
        if (!renew_sent && renew_time < next_event)  next_event = renew_time;
        if (!rebind_sent && rebind_time < next_event) next_event = rebind_time;

        auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           next_event - now)
                           .count();
        if (wait_ms < 0) wait_ms = 0;
        if (wait_ms > 60000) wait_ms = 60000; /* cap at 60 s */

        int ret = poll(fds, 2, static_cast<int>(wait_ms));

        if (ret < 0) {
            if (errno == EINTR) continue;
            LOG_ERR("poll: %s", strerror(errno));
            break;
        }

        now = clock::now();

        /* ---- Handle DHCPv6 replies ---------------------------------- */
        if (fds[0].revents & POLLIN) {
            DelegatedPrefix old_dp = dhcp->prefix();

            if (dhcp->handle_reply()) {
                const auto &new_dp = dhcp->prefix();

                /* Detect prefix change */
                bool changed = (std::memcmp(&old_dp.prefix,
                                            &new_dp.prefix, 16) != 0 ||
                                old_dp.prefix_len != new_dp.prefix_len);

                if (changed) {
                    LOG_INF("Prefix changed – reconfiguring LAN");
                    teardown_lan(cfg, lan, *ra);
                    apply_lan(cfg, lan, new_dp, *ra);
                } else {
                    /* Just update lifetimes in RAs */
                    ra->set_prefix(lan.subnet, 64,
                                   new_dp.valid_lt, new_dp.preferred_lt);
                }

                /* Reset renewal timers */
                lease_start = now;
                t1_secs = new_dp.t1 > 0 ? new_dp.t1 : new_dp.valid_lt / 2;
                t2_secs = new_dp.t2 > 0 ? new_dp.t2 : new_dp.valid_lt * 4 / 5;
                renew_time  = lease_start + std::chrono::seconds(t1_secs);
                rebind_time = lease_start + std::chrono::seconds(t2_secs);
                renew_sent  = false;
                rebind_sent = false;
            }
        }

        /* ---- Handle Router Solicitations ----------------------------- */
        if (fds[1].revents & POLLIN) {
            ra->handle_rs();
        }

        /* ---- Periodic RA --------------------------------------------- */
        if (now >= next_ra) {
            ra->send_ra();
            next_ra = now + std::chrono::seconds(cfg.ra_interval);
        }

        /* ---- DHCPv6 Renew (at T1) ----------------------------------- */
        if (!renew_sent && now >= renew_time) {
            dhcp->send_renew();
            renew_sent = true;
        }

        /* ---- DHCPv6 Rebind (at T2, if Renew got no reply) ----------- */
        if (!rebind_sent && now >= rebind_time) {
            dhcp->send_rebind();
            rebind_sent = true;
        }
    }

    /* ==== Shutdown ==================================================== */

    LOG_INF("Shutting down …");

    /* Deprecate prefix on clients */
    teardown_lan(cfg, lan, *ra);

    /* Release DHCPv6 lease */
    dhcp->send_release();

    LOG_INF("slaacbot stopped.");
    return 0;
}
