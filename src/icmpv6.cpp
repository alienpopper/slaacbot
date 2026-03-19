/*
 * icmpv6.cpp - ICMPv6 Router Advertisement / Router Solicitation handling.
 *
 * Uses an AF_INET6 / SOCK_RAW / IPPROTO_ICMPV6 socket.
 * The kernel handles the IPv6 header and ICMPv6 checksum automatically
 * for IPPROTO_ICMPV6 raw sockets on Linux.
 *
 * RA format (RFC 4861 §4.2):
 *   Type(1) Code(1) Checksum(2) CurHopLimit(1) M|O|flags(1)
 *   RouterLifetime(2) ReachableTime(4) RetransTimer(4)
 *   [Options: Source-LLA, Prefix-Info, MTU …]
 *
 * RS format (RFC 4861 §4.1):
 *   Type(1) Code(1) Checksum(2) Reserved(4) [Options]
 */
#include "icmpv6.h"
#include "log.h"
#include "netconfig.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <unistd.h>

/* ICMPv6 types */
static constexpr uint8_t ND_RA_TYPE = 134;
static constexpr uint8_t ND_RS_TYPE = 133;

/* ND option types */
static constexpr uint8_t ND_OPT_SLLA       = 1;  /* Source Link-Layer Address */
static constexpr uint8_t ND_OPT_PREFIX     = 3;  /* Prefix Information */
static constexpr uint8_t ND_OPT_MTU        = 5;  /* MTU */

/* Helper: append to vector */
static inline void put8(std::vector<uint8_t> &v, uint8_t x) {
    v.push_back(x);
}
static inline void put16(std::vector<uint8_t> &v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}
static inline void put32(std::vector<uint8_t> &v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

/* ===================================================================== */
/*  Construction / Destruction                                           */
/* ===================================================================== */

RAServer::RAServer(const std::string &iface, const Config &cfg)
    : iface_(iface),
      router_lifetime_(cfg.router_lifetime),
      hop_limit_(cfg.hop_limit),
      mtu_(cfg.mtu) {

    if_index_ = netconfig::get_ifindex(iface);
    netconfig::get_mac(iface, mac_);

    /* Create raw ICMPv6 socket */
    sock_ = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sock_ < 0)
        throw std::runtime_error(
            std::string("socket(RAW,ICMPv6) failed: ") + strerror(errno));

    /* Bind to the LAN interface */
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    if (setsockopt(sock_, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
        LOG_WRN("SO_BINDTODEVICE(RA): %s", strerror(errno));

    /* Set hop limit to 255 (required by RFC 4861) */
    int hops = 255;
    setsockopt(sock_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
    setsockopt(sock_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));

    /* Set outgoing multicast interface */
    int idx = if_index_;
    setsockopt(sock_, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof(idx));

    /* ICMPv6 filter: receive only Router Solicitations (type 133) */
    struct icmp6_filter filter;
    ICMP6_FILTER_SETBLOCKALL(&filter);
    ICMP6_FILTER_SETPASS(ND_RS_TYPE, &filter);
    setsockopt(sock_, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));

    /* Receive hop-limit ancillary data (for RFC 4861 validation) */
    int on = 1;
    setsockopt(sock_, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));

    /* Join all-routers multicast group (ff02::2) to receive RS */
    struct ipv6_mreq mreq{};
    inet_pton(AF_INET6, "ff02::2", &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = static_cast<unsigned>(if_index_);
    if (setsockopt(sock_, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                   &mreq, sizeof(mreq)) < 0)
        LOG_WRN("IPV6_JOIN_GROUP(ff02::2): %s", strerror(errno));

    LOG_INF("RA server on %s (ifindex %d)", iface_.c_str(), if_index_);
}

RAServer::~RAServer() {
    if (sock_ >= 0) close(sock_);
}

/* ===================================================================== */
/*  Prefix management                                                    */
/* ===================================================================== */

void RAServer::set_prefix(const struct in6_addr &prefix, int prefix_len,
                           uint32_t valid_lt, uint32_t preferred_lt) {
    prefix_     = prefix;
    prefix_len_ = prefix_len;
    valid_lt_   = valid_lt;
    preferred_lt_ = preferred_lt;
    LOG_INF("RA: advertising %s/%d (valid=%u pref=%u)",
            netconfig::to_string(prefix).c_str(), prefix_len,
            valid_lt, preferred_lt);
}

/* ===================================================================== */
/*  RA packet builder                                                    */
/* ===================================================================== */

std::vector<uint8_t> RAServer::build_ra(const struct in6_addr &pfx,
                                         int pfx_len,
                                         uint32_t valid_lt,
                                         uint32_t pref_lt) {
    std::vector<uint8_t> pkt;

    /* ---- ICMPv6 RA header (16 bytes) ---- */
    put8(pkt, ND_RA_TYPE);                          /* Type */
    put8(pkt, 0);                                    /* Code */
    put16(pkt, 0);                                   /* Checksum (kernel) */
    put8(pkt, static_cast<uint8_t>(hop_limit_));     /* CurHopLimit */
    put8(pkt, 0);                                    /* M=0 O=0 (SLAAC) */
    put16(pkt, static_cast<uint16_t>(router_lifetime_)); /* Router Lifetime */
    put32(pkt, 0);                                   /* Reachable Time */
    put32(pkt, 0);                                   /* Retrans Timer */

    /* ---- Option: Source Link-Layer Address (8 bytes) ---- */
    put8(pkt, ND_OPT_SLLA);                          /* Type */
    put8(pkt, 1);                                     /* Length (units of 8) */
    pkt.insert(pkt.end(), mac_, mac_ + 6);

    /* ---- Option: Prefix Information (32 bytes) ---- */
    put8(pkt, ND_OPT_PREFIX);                         /* Type */
    put8(pkt, 4);                                     /* Length (units of 8) */
    put8(pkt, static_cast<uint8_t>(pfx_len));         /* Prefix Length */
    put8(pkt, 0xC0);                                  /* L=1 A=1 flags (SLAAC) */
    put32(pkt, valid_lt);                             /* Valid Lifetime */
    put32(pkt, pref_lt);                              /* Preferred Lifetime */
    put32(pkt, 0);                                    /* Reserved */
    pkt.insert(pkt.end(), pfx.s6_addr, pfx.s6_addr + 16);

    /* ---- Option: MTU (8 bytes, optional) ---- */
    if (mtu_ > 0) {
        put8(pkt, ND_OPT_MTU);
        put8(pkt, 1);                                 /* Length (units of 8) */
        put16(pkt, 0);                                /* Reserved */
        put32(pkt, static_cast<uint32_t>(mtu_));
    }

    return pkt;
}

/* ===================================================================== */
/*  Sending                                                              */
/* ===================================================================== */

void RAServer::send_raw(const std::vector<uint8_t> &pkt,
                         const struct sockaddr_in6 &dest) {
    ssize_t n = sendto(sock_, pkt.data(), pkt.size(), 0,
                       reinterpret_cast<const struct sockaddr *>(&dest),
                       sizeof(dest));
    if (n < 0)
        LOG_ERR("RA sendto: %s", strerror(errno));
}

void RAServer::send_ra() {
    if (prefix_len_ == 0) return; /* no prefix set yet */

    /* Rate-limit: RFC 4861 §6.2.6 */
    auto now = std::chrono::steady_clock::now();
    if (now - last_ra_time_ < std::chrono::seconds(MIN_RA_DELAY_S))
        return;

    auto pkt = build_ra(prefix_, prefix_len_, valid_lt_, preferred_lt_);

    /* Send to ff02::1 (all-nodes) */
    struct sockaddr_in6 dest{};
    dest.sin6_family   = AF_INET6;
    dest.sin6_scope_id = static_cast<uint32_t>(if_index_);
    inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr);

    send_raw(pkt, dest);
    last_ra_time_ = now;
    LOG_DBG("RA: sent unsolicited advertisement");
}

void RAServer::send_deprecation(const struct in6_addr &old_prefix,
                                 int prefix_len) {
    LOG_INF("RA: deprecating old prefix %s/%d",
            netconfig::to_string(old_prefix).c_str(), prefix_len);

    /* Send RA with the old prefix and lifetimes = 0 */
    auto pkt = build_ra(old_prefix, prefix_len, 0, 0);

    struct sockaddr_in6 dest{};
    dest.sin6_family   = AF_INET6;
    dest.sin6_scope_id = static_cast<uint32_t>(if_index_);
    inet_pton(AF_INET6, "ff02::1", &dest.sin6_addr);

    /* Send a few times to be sure clients get it */
    for (int i = 0; i < 3; ++i)
        send_raw(pkt, dest);
}

/* ===================================================================== */
/*  Receiving Router Solicitations                                       */
/* ===================================================================== */

bool RAServer::handle_rs() {
    uint8_t buf[1500];
    struct sockaddr_in6 src{};
    struct iovec iov{};
    iov.iov_base = buf;
    iov.iov_len  = sizeof(buf);

    /* Ancillary data buffer for hop limit */
    uint8_t cmsg_buf[CMSG_SPACE(sizeof(int))];

    struct msghdr mhdr{};
    mhdr.msg_name       = &src;
    mhdr.msg_namelen    = sizeof(src);
    mhdr.msg_iov        = &iov;
    mhdr.msg_iovlen     = 1;
    mhdr.msg_control    = cmsg_buf;
    mhdr.msg_controllen = sizeof(cmsg_buf);

    ssize_t n = recvmsg(sock_, &mhdr, MSG_DONTWAIT);
    if (n < 8) return false; /* RS is at least 8 bytes */

    if (buf[0] != ND_RS_TYPE || buf[1] != 0)
        return false;

    /* RFC 4861 §6.1.1: hop limit must be 255 (on-link check) */
    int hoplimit = -1;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mhdr);
         cmsg != nullptr;
         cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6 &&
            cmsg->cmsg_type  == IPV6_HOPLIMIT) {
            std::memcpy(&hoplimit, CMSG_DATA(cmsg), sizeof(hoplimit));
            break;
        }
    }
    if (hoplimit != 255) {
        LOG_DBG("RA: discarding RS with hop limit %d (expected 255)", hoplimit);
        return false;
    }

    LOG_DBG("RA: received Router Solicitation from %s",
            netconfig::to_string(src.sin6_addr).c_str());

    /* Respond with an RA (rate-limited by send_ra) */
    send_ra();
    return true;
}
