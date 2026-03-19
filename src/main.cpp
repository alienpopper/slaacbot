/*
 * main.cpp - slaacbot daemon entry point (threaded, multi-LAN).
 *
 * Architecture:
 *
 *   WAN thread  – Owns DHCPv6Client exclusively.  Handles the initial
 *                 Solicit/Request exchange, T1 Renew, T2 Rebind, and
 *                 incoming Reply processing.  When the delegated prefix
 *                 changes (or is first obtained), it updates SharedState
 *                 under the mutex and signals every LAN thread via their
 *                 individual eventfds.
 *
 *   LAN threads – One per downstream interface.  Each owns its own
 *                 RAServer.  Sends periodic Router Advertisements,
 *                 responds to Router Solicitations, and watches for
 *                 prefix-change notifications via its eventfd.
 *                 On notification it tears down old LAN config, carves
 *                 its assigned /64, applies the new prefix, and
 *                 immediately advertises it.
 *
 *   Main thread – Parses config, prepares interfaces, launches all
 *                 threads, waits for SIGINT/SIGTERM, then signals
 *                 shutdown and joins every thread.
 *
 * Thread safety:
 *   - SharedState is protected by a std::mutex.
 *   - Cross-thread wake-ups use Linux eventfd (pollable).
 *   - RAServer and DHCPv6Client are never touched from outside
 *     the thread that owns them.
 */
#include "config.h"
#include "dhcpv6.h"
#include "icmpv6.h"
#include "log.h"
#include "netconfig.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <thread>
#include <unistd.h>
#include <vector>

/* ====================================================================== */
/*  Globals                                                               */
/* ====================================================================== */

static std::atomic<bool> g_running{true};

static void signal_handler(int) { g_running.store(false); }

/* ====================================================================== */
/*  EventFD helper – pollable cross-thread signal                         */
/* ====================================================================== */

class EventFD {
public:
    EventFD() {
        fd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (fd_ < 0)
            throw std::runtime_error(
                std::string("eventfd: ") + strerror(errno));
    }
    ~EventFD() { if (fd_ >= 0) close(fd_); }

    EventFD(const EventFD &)            = delete;
    EventFD &operator=(const EventFD &) = delete;

    /** Signal (wake the other thread). */
    void signal() {
        uint64_t val = 1;
        [[maybe_unused]] auto n = write(fd_, &val, sizeof(val));
    }

    /** Consume the signal (call after poll reports POLLIN). */
    void consume() {
        uint64_t val;
        [[maybe_unused]] auto n = read(fd_, &val, sizeof(val));
    }

    int fd() const { return fd_; }

private:
    int fd_ = -1;
};

/* ====================================================================== */
/*  Shared state between WAN thread and all LAN threads                   */
/* ====================================================================== */

struct SharedState {
    std::mutex          mtx;

    /* Written by WAN thread, read by LAN threads */
    DelegatedPrefix     dp{};              /* current delegated prefix   */
    uint64_t            generation = 0;    /* incremented on every change */

    /* State file for crash recovery (written by LAN threads) */
    std::string                          state_path;
    std::vector<netconfig::LanStateEntry> lan_entries;
};

/* ====================================================================== */
/*  LAN state (owned exclusively by one LAN thread)                       */
/* ====================================================================== */

struct LanState {
    struct in6_addr subnet{};      /* /64 carved from delegated prefix   */
    struct in6_addr host_addr{};   /* ::1 inside the subnet              */
    int             prefix_len = 64;
    bool            configured = false;
};

/* ---- Apply / tear down LAN configuration ----------------------------- */

static void apply_lan(const LanConfig &lcfg, const Config &cfg,
                      LanState &lan, const DelegatedPrefix &dp,
                      RAServer &ra, SharedState &shared) {
    lan.subnet = netconfig::carve_subnet(dp.prefix, dp.prefix_len,
                                         lcfg.subnet_index, 64);
    lan.prefix_len = 64;
    lan.host_addr  = netconfig::make_host_addr(lan.subnet, 64, 1);

    LOG_INF("LAN[%s] config: %s/64  host %s",
            lcfg.interface.c_str(),
            netconfig::to_string(lan.subnet).c_str(),
            netconfig::to_string(lan.host_addr).c_str());

    netconfig::add_address(lcfg.interface, lan.host_addr, 64);
    netconfig::add_route(lan.subnet, 64, lcfg.interface);
    lan.configured = true;

    ra.set_prefix(lan.subnet, 64, dp.valid_lt, dp.preferred_lt);
    ra.send_ra();

    /* Persist state for crash recovery */
    {
        std::lock_guard<std::mutex> lk(shared.mtx);
        /* Update or insert this interface's entry */
        bool found = false;
        for (auto &e : shared.lan_entries) {
            if (e.interface == lcfg.interface) {
                e.subnet     = lan.subnet;
                e.host_addr  = lan.host_addr;
                e.prefix_len = lan.prefix_len;
                found = true;
                break;
            }
        }
        if (!found) {
            netconfig::LanStateEntry entry;
            entry.interface  = lcfg.interface;
            entry.subnet     = lan.subnet;
            entry.host_addr  = lan.host_addr;
            entry.prefix_len = lan.prefix_len;
            shared.lan_entries.push_back(std::move(entry));
        }
        netconfig::save_state(shared.state_path, shared.lan_entries);
    }
}

static void teardown_lan(const LanConfig &lcfg, LanState &lan,
                         RAServer &ra, SharedState &shared) {
    if (!lan.configured) return;
    LOG_INF("LAN[%s] tearing down", lcfg.interface.c_str());

    ra.send_deprecation(lan.subnet, 64);
    netconfig::del_route(lan.subnet, 64, lcfg.interface);
    netconfig::del_address(lcfg.interface, lan.host_addr, 64);
    lan.configured = false;

    /* Remove this interface from persisted state */
    {
        std::lock_guard<std::mutex> lk(shared.mtx);
        auto &v = shared.lan_entries;
        v.erase(std::remove_if(v.begin(), v.end(),
                    [&](const netconfig::LanStateEntry &e) {
                        return e.interface == lcfg.interface;
                    }),
                v.end());
        if (v.empty())
            netconfig::remove_state(shared.state_path);
        else
            netconfig::save_state(shared.state_path, v);
    }
}

/* ====================================================================== */
/*  WAN thread                                                            */
/* ====================================================================== */

static void wan_thread_fn(const Config &cfg, SharedState &shared,
                          std::vector<EventFD*> &lan_notifiers,
                          EventFD &stop_event) {
    LOG_INF("WAN thread started on %s", cfg.wan_interface.c_str());

    auto notify_all_lans = [&]() {
        for (auto *ev : lan_notifiers)
            ev->signal();
    };

    /* ---- Create DHCPv6 client --------------------------------------- */
    uint8_t wan_mac[6];
    try {
        netconfig::get_mac(cfg.wan_interface, wan_mac);
    } catch (const std::exception &e) {
        LOG_ERR("WAN: %s", e.what());
        g_running.store(false);
        notify_all_lans();
        return;
    }

    std::unique_ptr<DHCPv6Client> dhcp;
    try {
        dhcp = std::make_unique<DHCPv6Client>(
            cfg.wan_interface, wan_mac, cfg.iaid, cfg.prefix_length,
            cfg.retransmit_timeout, cfg.max_retransmit);
    } catch (const std::exception &e) {
        LOG_ERR("WAN DHCPv6 init: %s", e.what());
        g_running.store(false);
        notify_all_lans();
        return;
    }

    /* ---- Obtain initial prefix -------------------------------------- */
    while (g_running.load() && !dhcp->obtain_prefix()) {
        LOG_WRN("DHCPv6: retrying in %d seconds …", cfg.retransmit_timeout);
        struct pollfd pfd{};
        pfd.fd     = stop_event.fd();
        pfd.events = POLLIN;
        poll(&pfd, 1, cfg.retransmit_timeout * 1000);
        if (pfd.revents & POLLIN) { stop_event.consume(); break; }
    }
    if (!g_running.load()) return;

    /* ---- Publish initial prefix to shared state --------------------- */
    {
        std::lock_guard<std::mutex> lk(shared.mtx);
        shared.dp = dhcp->prefix();
        shared.generation++;
    }
    notify_all_lans();

    /* ---- Compute renewal timers ------------------------------------- */
    using clock = std::chrono::steady_clock;
    auto lease_start = clock::now();

    auto t1_secs = dhcp->prefix().t1 > 0
                       ? dhcp->prefix().t1
                       : dhcp->prefix().valid_lt / 2;
    auto t2_secs = dhcp->prefix().t2 > 0
                       ? dhcp->prefix().t2
                       : dhcp->prefix().valid_lt * 4 / 5;

    auto renew_time  = lease_start + std::chrono::seconds(t1_secs);
    auto rebind_time = lease_start + std::chrono::seconds(t2_secs);
    bool renew_sent  = false;
    bool rebind_sent = false;

    LOG_INF("WAN event loop  (T1=%us  T2=%us)", t1_secs, t2_secs);

    /* ---- WAN poll loop ---------------------------------------------- */
    struct pollfd fds[2];
    fds[0].fd     = dhcp->fd();
    fds[0].events = POLLIN;
    fds[1].fd     = stop_event.fd();
    fds[1].events = POLLIN;

    while (g_running.load()) {
        auto now = clock::now();

        auto next_event = renew_time;
        if (!renew_sent && renew_time < next_event)  next_event = renew_time;
        if (!rebind_sent && rebind_time < next_event) next_event = rebind_time;

        auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           next_event - now).count();
        if (wait_ms < 0) wait_ms = 0;
        if (wait_ms > 60000) wait_ms = 60000;

        int ret = poll(fds, 2, static_cast<int>(wait_ms));
        if (ret < 0 && errno != EINTR) {
            LOG_ERR("WAN poll: %s", strerror(errno));
            break;
        }

        /* Stop signal? */
        if (fds[1].revents & POLLIN) {
            stop_event.consume();
            break;
        }

        now = clock::now();

        /* ---- DHCPv6 reply ------------------------------------------- */
        if (fds[0].revents & POLLIN) {
            DelegatedPrefix old_dp = dhcp->prefix();

            if (dhcp->handle_reply()) {
                const auto &new_dp = dhcp->prefix();

                bool changed = (std::memcmp(&old_dp.prefix,
                                            &new_dp.prefix, 16) != 0 ||
                                old_dp.prefix_len != new_dp.prefix_len);

                /* Publish to shared state */
                {
                    std::lock_guard<std::mutex> lk(shared.mtx);
                    shared.dp = new_dp;
                    if (changed) shared.generation++;
                }
                if (changed || new_dp.valid_lt != old_dp.valid_lt ||
                    new_dp.preferred_lt != old_dp.preferred_lt) {
                    notify_all_lans();
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

        /* ---- T1 Renew ----------------------------------------------- */
        if (!renew_sent && now >= renew_time) {
            dhcp->send_renew();
            renew_sent = true;
        }

        /* ---- T2 Rebind ---------------------------------------------- */
        if (!rebind_sent && now >= rebind_time) {
            dhcp->send_rebind();
            rebind_sent = true;
        }
    }

    /* ---- Release the lease ------------------------------------------ */
    dhcp->send_release();
    LOG_INF("WAN thread exiting");
}

/* ====================================================================== */
/*  LAN thread (one per downstream interface)                             */
/* ====================================================================== */

static void lan_thread_fn(const Config &cfg, const LanConfig &lcfg,
                          SharedState &shared,
                          EventFD &lan_notify, EventFD &stop_event) {
    LOG_INF("LAN thread started on %s (subnet_index=%d)",
            lcfg.interface.c_str(), lcfg.subnet_index);

    /* ---- Create RA server ------------------------------------------- */
    std::unique_ptr<RAServer> ra;
    try {
        ra = std::make_unique<RAServer>(lcfg.interface, cfg);
    } catch (const std::exception &e) {
        LOG_ERR("LAN[%s] RA init: %s",
                lcfg.interface.c_str(), e.what());
        g_running.store(false);
        return;
    }

    LanState lan;
    uint64_t seen_gen = 0;

    using clock = std::chrono::steady_clock;
    auto next_ra = clock::now();

    /* ---- LAN poll loop ---------------------------------------------- */
    struct pollfd fds[3];
    fds[0].fd     = ra->fd();
    fds[0].events = POLLIN;
    fds[1].fd     = lan_notify.fd();
    fds[1].events = POLLIN;
    fds[2].fd     = stop_event.fd();
    fds[2].events = POLLIN;

    while (g_running.load()) {
        auto now = clock::now();
        auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           next_ra - now).count();
        if (wait_ms < 0) wait_ms = 0;
        if (wait_ms > 60000) wait_ms = 60000;

        int ret = poll(fds, 3, static_cast<int>(wait_ms));
        if (ret < 0 && errno != EINTR) {
            LOG_ERR("LAN[%s] poll: %s",
                    lcfg.interface.c_str(), strerror(errno));
            break;
        }

        /* Stop signal? */
        if (fds[2].revents & POLLIN) {
            stop_event.consume();
            break;
        }

        now = clock::now();

        /* ---- Prefix update from WAN thread -------------------------- */
        if (fds[1].revents & POLLIN) {
            lan_notify.consume();

            DelegatedPrefix dp;
            uint64_t gen;
            {
                std::lock_guard<std::mutex> lk(shared.mtx);
                dp  = shared.dp;
                gen = shared.generation;
            }

            if (gen != seen_gen && dp.valid) {
                if (lan.configured) {
                    LOG_INF("LAN[%s] prefix changed – reconfiguring",
                            lcfg.interface.c_str());
                    teardown_lan(lcfg, lan, *ra, shared);
                }
                apply_lan(lcfg, cfg, lan, dp, *ra, shared);
                seen_gen = gen;
            } else if (dp.valid && lan.configured) {
                /* Lifetime refresh only */
                ra->set_prefix(lan.subnet, 64,
                               dp.valid_lt, dp.preferred_lt);
            }
        }

        /* ---- Router Solicitations ----------------------------------- */
        if (fds[0].revents & POLLIN) {
            ra->handle_rs();
        }

        /* ---- Periodic RA -------------------------------------------- */
        if (now >= next_ra) {
            ra->send_ra();
            next_ra = now + std::chrono::seconds(cfg.ra_interval);
        }
    }

    /* ---- Shutdown: deprecate prefix on clients ---------------------- */
    teardown_lan(lcfg, lan, *ra, shared);
    LOG_INF("LAN[%s] thread exiting", lcfg.interface.c_str());
}

/* ====================================================================== */
/*  Usage                                                                 */
/* ====================================================================== */

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

    /* ---- Daemonise if requested -------------------------------------- */
    if (daemonise) {
        if (daemon(0, 0) < 0) {
            LOG_ERR("daemon(): %s", strerror(errno));
            return 1;
        }
    }

    /* ---- Prepare interfaces ------------------------------------------ */
    try {
        netconfig::enable_forwarding();
        netconfig::set_accept_ra(cfg.wan_interface, 2);
        for (const auto &lcfg : cfg.lans)
            netconfig::set_accept_ra(lcfg.interface, 0);
    } catch (const std::exception &e) {
        LOG_ERR("Interface setup: %s", e.what());
        return 1;
    }

    /* ---- Shared state & event fds ------------------------------------ */
    SharedState shared;
    shared.state_path = netconfig::STATE_FILE;

    /* ---- Recover from previous crash --------------------------------- */
    {
        auto stale = netconfig::load_state(shared.state_path);
        for (const auto &e : stale) {
            LOG_INF("Cleanup stale: %s  %s/%d  host %s",
                    e.interface.c_str(),
                    netconfig::to_string(e.subnet).c_str(),
                    e.prefix_len,
                    netconfig::to_string(e.host_addr).c_str());
            netconfig::del_route(e.subnet, e.prefix_len, e.interface);
            netconfig::del_address(e.interface, e.host_addr, e.prefix_len);
        }
        if (!stale.empty())
            netconfig::remove_state(shared.state_path);
    }

    /*
     * One notify + one stop eventfd per LAN thread.
     * We use unique_ptr because EventFD is non-copyable/non-movable.
     */
    size_t num_lans = cfg.lans.size();

    std::vector<std::unique_ptr<EventFD>> lan_notifiers;
    std::vector<std::unique_ptr<EventFD>> lan_stops;
    for (size_t i = 0; i < num_lans; ++i) {
        lan_notifiers.push_back(std::make_unique<EventFD>());
        lan_stops.push_back(std::make_unique<EventFD>());
    }

    /* Build a raw-pointer vector for the WAN thread to iterate over. */
    std::vector<EventFD*> notifier_ptrs;
    for (auto &p : lan_notifiers)
        notifier_ptrs.push_back(p.get());

    EventFD wan_stop;

    /* ---- Launch WAN thread ------------------------------------------- */
    std::thread wan(wan_thread_fn,
                    std::cref(cfg), std::ref(shared),
                    std::ref(notifier_ptrs), std::ref(wan_stop));

    /* ---- Launch LAN threads ----------------------------------------- */
    std::vector<std::thread> lan_threads;
    for (size_t i = 0; i < num_lans; ++i) {
        lan_threads.emplace_back(lan_thread_fn,
                                 std::cref(cfg),
                                 std::cref(cfg.lans[i]),
                                 std::ref(shared),
                                 std::ref(*lan_notifiers[i]),
                                 std::ref(*lan_stops[i]));
    }

    /* ---- Signal handling (main thread only) -------------------------- */
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    LOG_INF("slaacbot running  (WAN=%s  %zu LAN interface(s))",
            cfg.wan_interface.c_str(), num_lans);

    /* Block until a signal sets g_running = false */
    while (g_running.load()) {
        pause();   /* sleep until any signal */
    }

    /* ---- Shutdown: signal all threads -------------------------------- */
    LOG_INF("Shutting down …");
    wan_stop.signal();
    for (auto &s : lan_stops)
        s->signal();

    wan.join();
    for (auto &t : lan_threads)
        t.join();

    /* State file should already be empty, but ensure it's gone */
    netconfig::remove_state(shared.state_path);

    LOG_INF("slaacbot stopped.");
    return 0;
}
