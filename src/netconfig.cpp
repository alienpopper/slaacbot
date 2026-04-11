/*
 * netconfig.cpp - Implementation of low-level network helpers.
 */
#include "netconfig.h"
#include "log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <net/if.h>
#include <regex>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace netconfig {

/* ===================================================================== */
/*  Command execution                                                    */
/* ===================================================================== */

int run_cmd(const std::vector<std::string> &args, std::string *output,
            bool quiet) {
    /* Build a debug string */
    std::string dbg;
    for (auto &a : args) { dbg += a; dbg += ' '; }
    if (!quiet)
        LOG_INF("exec: %s", dbg.c_str());

    int pipefd[2] = {-1, -1};
    if (output) {
        if (pipe(pipefd) < 0)
            throw std::runtime_error("pipe() failed");
    }

    pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");

    if (pid == 0) {
        /* Child */
        if (output) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);
        }
        std::vector<char *> argv;
        for (auto &a : args)
            argv.push_back(const_cast<char *>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }

    /* Parent */
    if (output) {
        close(pipefd[1]);
        char buf[1024];
        ssize_t n;
        output->clear();
        while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
            output->append(buf, static_cast<size_t>(n));
        close(pipefd[0]);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (rc != 0)
        LOG_DBG("  exit %d", rc);
    return rc;
}

/* ===================================================================== */
/*  Interface information                                                */
/* ===================================================================== */

void get_mac(const std::string &iface, uint8_t mac[6]) {
    std::string out;
    int rc = run_cmd({"ip", "link", "show", "dev", iface}, &out);
    if (rc != 0)
        throw std::runtime_error("Cannot query interface " + iface);

    std::regex re("link/ether\\s+([0-9a-fA-F:]{17})");
    std::smatch m;
    if (!std::regex_search(out, m, re))
        throw std::runtime_error("No MAC address found on " + iface);

    std::string ms = m[1].str();
    unsigned int b[6];
    if (sscanf(ms.c_str(), "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        throw std::runtime_error("Bad MAC format on " + iface);

    for (int i = 0; i < 6; ++i) mac[i] = static_cast<uint8_t>(b[i]);
    LOG_DBG("MAC %s = %s", iface.c_str(), ms.c_str());
}

int get_ifindex(const std::string &iface) {
    unsigned idx = if_nametoindex(iface.c_str());
    if (idx == 0)
        throw std::runtime_error("Unknown interface: " + iface);
    return static_cast<int>(idx);
}

/* ===================================================================== */
/*  Address / route management                                           */
/* ===================================================================== */

void add_address(const std::string &iface,
                 const struct in6_addr &addr, int prefix_len) {
    std::string a = to_string(addr) + "/" + std::to_string(prefix_len);
    LOG_INF("addr add %s dev %s", a.c_str(), iface.c_str());
    run_cmd({"ip", "-6", "addr", "add", a, "dev", iface});
}

void del_address(const std::string &iface,
                 const struct in6_addr &addr, int prefix_len) {
    std::string a = to_string(addr) + "/" + std::to_string(prefix_len);
    LOG_INF("addr del %s dev %s", a.c_str(), iface.c_str());
    run_cmd({"ip", "-6", "addr", "del", a, "dev", iface});
}

void add_route(const struct in6_addr &prefix, int prefix_len,
               const std::string &iface) {
    std::string r = to_string(prefix) + "/" + std::to_string(prefix_len);
    LOG_INF("route add %s dev %s", r.c_str(), iface.c_str());
    run_cmd({"ip", "-6", "route", "add", r, "dev", iface});
}

void del_route(const struct in6_addr &prefix, int prefix_len,
               const std::string &iface) {
    std::string r = to_string(prefix) + "/" + std::to_string(prefix_len);
    LOG_INF("route del %s dev %s", r.c_str(), iface.c_str());
    run_cmd({"ip", "-6", "route", "del", r, "dev", iface});
}

/* ===================================================================== */
/*  Address / route presence checks                                      */
/* ===================================================================== */

bool has_address(const std::string &iface,
                 const struct in6_addr &addr, int prefix_len) {
    std::string a = to_string(addr) + "/" + std::to_string(prefix_len);
    std::string out;
    run_cmd({"ip", "-6", "addr", "show", "dev", iface}, &out, /*quiet=*/true);
    return out.find(a) != std::string::npos;
}

bool has_route(const struct in6_addr &prefix, int prefix_len,
               const std::string &iface) {
    std::string r = to_string(prefix) + "/" + std::to_string(prefix_len);
    std::string out;
    run_cmd({"ip", "-6", "route", "show", "dev", iface}, &out, /*quiet=*/true);
    return out.find(r) != std::string::npos;
}

/* ===================================================================== */
/*  Sysctl helpers                                                       */
/* ===================================================================== */

void enable_forwarding() {
    LOG_INF("Enabling IPv6 forwarding");

    FILE *f = fopen("/proc/sys/net/ipv6/conf/all/forwarding", "w");
    if (f) { fputs("1\n", f); fclose(f); return; }

    /* Fallback */
    run_cmd({"sysctl", "-w", "net.ipv6.conf.all.forwarding=1"});
}

void set_accept_ra(const std::string &iface, int value) {
    std::string path =
        "/proc/sys/net/ipv6/conf/" + iface + "/accept_ra";

    FILE *f = fopen(path.c_str(), "w");
    if (f) {
        fprintf(f, "%d\n", value);
        fclose(f);
        LOG_INF("accept_ra=%d on %s", value, iface.c_str());
        return;
    }
    std::string kv =
        "net.ipv6.conf." + iface + ".accept_ra=" + std::to_string(value);
    run_cmd({"sysctl", "-w", kv});
}

/* ===================================================================== */
/*  Prefix arithmetic                                                    */
/* ===================================================================== */

struct in6_addr carve_subnet(const struct in6_addr &prefix,
                             int prefix_len,
                             int subnet_index,
                             int target_len) {
    if (target_len <= prefix_len)
        throw std::runtime_error("target_len must be > prefix_len");

    int subnet_bits = target_len - prefix_len;
    int max_subnets = 1 << subnet_bits;
    if (subnet_index < 0 || subnet_index >= max_subnets)
        throw std::runtime_error("subnet_index out of range");

    /* Work on a mutable copy stored as a 128-bit big-endian array */
    struct in6_addr result = prefix;

    /*
     * We need to place subnet_index into bits [prefix_len .. target_len)
     * of the 128-bit address.  The bits are numbered left-to-right
     * (MSB = bit 0).
     *
     * Byte position of the first affected bit: prefix_len / 8
     * Bit offset within that byte:             prefix_len % 8
     *
     * For the common case /56 → /64, subnet_bits == 8 and the
     * subnet_index fits in a single byte at offset 7.
     */
    int shift = 128 - target_len;              /* bits below target_len */
    /* Convert address to a 128-bit integer, OR in the index, convert back. */
    /* Quick approach: work byte-by-byte from the relevant position. */

    /* Place index starting at bit position prefix_len (0-indexed from MSB) */
    int start_byte  = prefix_len / 8;
    int start_bit   = prefix_len % 8;

    /* Zero the subnet bits first */
    for (int b = prefix_len; b < target_len; ++b) {
        int byte_pos = b / 8;
        int bit_pos  = 7 - (b % 8);
        result.s6_addr[byte_pos] &= ~(1u << bit_pos);
    }

    /* Write subnet_index into those bits (MSB first) */
    for (int i = 0; i < subnet_bits; ++i) {
        int bit_val  = (subnet_index >> (subnet_bits - 1 - i)) & 1;
        int b        = prefix_len + i;
        int byte_pos = b / 8;
        int bit_pos  = 7 - (b % 8);
        if (bit_val)
            result.s6_addr[byte_pos] |= (1u << bit_pos);
    }

    (void)shift;
    (void)start_byte;
    (void)start_bit;

    return result;
}

struct in6_addr make_host_addr(const struct in6_addr &prefix,
                               int prefix_len,
                               uint64_t host_id) {
    struct in6_addr result = prefix;

    /* Zero host part, then OR in host_id (low 64 bits). */
    int full_bytes = prefix_len / 8;
    int extra_bits = prefix_len % 8;

    /* Clear everything after the prefix */
    if (extra_bits) {
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - extra_bits));
        result.s6_addr[full_bytes] &= mask;
        full_bytes++;
    }
    for (int i = full_bytes; i < 16; ++i)
        result.s6_addr[i] = 0;

    /* OR in host_id, placed in the rightmost 64 bits */
    for (int i = 0; i < 8; ++i) {
        result.s6_addr[15 - i] |=
            static_cast<uint8_t>((host_id >> (i * 8)) & 0xFF);
    }

    return result;
}

/* ===================================================================== */
/*  Formatting                                                           */
/* ===================================================================== */

std::string to_string(const struct in6_addr &a) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return buf;
}

struct in6_addr from_string(const std::string &s) {
    struct in6_addr a{};
    if (inet_pton(AF_INET6, s.c_str(), &a) != 1)
        throw std::runtime_error("Bad IPv6 address: " + s);
    return a;
}

/* ===================================================================== */
/*  State file (crash recovery)                                          */
/* ===================================================================== */

/*
 * Format: one line per LAN interface:
 *   <interface> <subnet> <host_addr> <prefix_len>
 * e.g.:
 *   eth1 2001:db8:1:1:: 2001:db8:1:1::1 64
 */

void save_state(const std::string &path,
                const std::vector<LanStateEntry> &entries) {
    std::string tmp = path + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        LOG_WRN("Cannot write state file %s: %s", tmp.c_str(), strerror(errno));
        return;
    }
    FILE *f = fdopen(fd, "w");
    if (!f) {
        LOG_WRN("fdopen state file %s: %s", tmp.c_str(), strerror(errno));
        close(fd);
        return;
    }
    for (const auto &e : entries) {
        fprintf(f, "%s %s %s %d\n",
                e.interface.c_str(),
                to_string(e.subnet).c_str(),
                to_string(e.host_addr).c_str(),
                e.prefix_len);
    }
    fclose(f);
    if (rename(tmp.c_str(), path.c_str()) != 0)
        LOG_WRN("rename %s -> %s: %s", tmp.c_str(), path.c_str(), strerror(errno));
    else
        LOG_DBG("State saved (%zu entries)", entries.size());
}

std::vector<LanStateEntry> load_state(const std::string &path) {
    std::vector<LanStateEntry> entries;
    FILE *f = fopen(path.c_str(), "r");
    if (!f) return entries;   /* no previous state */

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char iface[64], subnet[INET6_ADDRSTRLEN], host[INET6_ADDRSTRLEN];
        int plen = 0;
        if (sscanf(line, "%63s %45s %45s %d", iface, subnet, host, &plen) == 4) {
            LanStateEntry e;
            e.interface  = iface;
            e.prefix_len = plen;
            if (inet_pton(AF_INET6, subnet, &e.subnet) == 1 &&
                inet_pton(AF_INET6, host,   &e.host_addr) == 1) {
                entries.push_back(std::move(e));
            } else {
                LOG_WRN("State file: bad address in line: %s", line);
            }
        }
    }
    fclose(f);
    LOG_INF("Loaded %zu stale state entries from %s", entries.size(), path.c_str());
    return entries;
}

void remove_state(const std::string &path) {
    if (unlink(path.c_str()) == 0)
        LOG_DBG("Removed state file %s", path.c_str());
}

}  // namespace netconfig
