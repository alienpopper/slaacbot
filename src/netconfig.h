/*
 * netconfig.h - Low-level IPv6 network configuration via the "ip" tool.
 *
 * All interaction with the kernel's networking stack goes through
 * fork/exec of the "ip" binary.  No systemd, NetworkManager, or
 * other high-level service is touched.
 */
#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <vector>

namespace netconfig {

/* ---- command execution ------------------------------------------------ */

/**
 * Run an external command, capture stdout+stderr.
 * Returns the exit status.  Output is stored in *output when non-null.
 */
int  run_cmd(const std::vector<std::string> &args,
             std::string *output = nullptr);

/* ---- interface information -------------------------------------------- */

void get_mac(const std::string &iface, uint8_t mac[6]);
int  get_ifindex(const std::string &iface);

/* ---- address / route management --------------------------------------- */

void add_address(const std::string &iface,
                 const struct in6_addr &addr, int prefix_len);
void del_address(const std::string &iface,
                 const struct in6_addr &addr, int prefix_len);

void add_route(const struct in6_addr &prefix, int prefix_len,
               const std::string &iface);
void del_route(const struct in6_addr &prefix, int prefix_len,
               const std::string &iface);

/* ---- sysctl helpers --------------------------------------------------- */

void enable_forwarding();
void set_accept_ra(const std::string &iface, int value);

/* ---- prefix arithmetic ----------------------------------------------- */

/**
 * Carve subnet #subnet_index of size /target_len from a delegated prefix.
 * E.g. carve_subnet(prefix, 56, 0, 64) returns the first /64.
 */
struct in6_addr carve_subnet(const struct in6_addr &prefix,
                             int prefix_len,
                             int subnet_index,
                             int target_len = 64);

/**
 * Form a host address: prefix | host_id  (host_id in the low bits).
 */
struct in6_addr make_host_addr(const struct in6_addr &prefix,
                               int prefix_len,
                               uint64_t host_id = 1);

/* ---- formatting ------------------------------------------------------- */

std::string      to_string(const struct in6_addr &a);
struct in6_addr  from_string(const std::string &s);

}  // namespace netconfig
