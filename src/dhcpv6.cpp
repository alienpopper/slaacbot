/*
 * dhcpv6.cpp - DHCPv6 Prefix-Delegation client implementation.
 *
 * Implements the 4-message exchange (SARR):
 *   Solicit  →  Advertise  →  Request  →  Reply
 * and the renewal path:
 *   Renew / Rebind  →  Reply
 *
 * All packets are hand-built; no external DHCPv6 library is used.
 */
#include "dhcpv6.h"
#include "log.h"
#include "netconfig.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <net/if.h>
#include <poll.h>
#include <stdexcept>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

/* ---- Constants -------------------------------------------------------- */

static constexpr uint16_t DHCP6_CLIENT_PORT = 546;
static constexpr uint16_t DHCP6_SERVER_PORT = 547;

/* All_DHCP_Relay_Agents_and_Servers */
static const char *DHCP6_MCAST = "ff02::1:2";

/* ---- Byte helpers ----------------------------------------------------- */

void DHCPv6Client::put_u16(std::vector<uint8_t> &buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v));
}

void DHCPv6Client::put_u32(std::vector<uint8_t> &buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v >> 24));
    buf.push_back(static_cast<uint8_t>(v >> 16));
    buf.push_back(static_cast<uint8_t>(v >> 8));
    buf.push_back(static_cast<uint8_t>(v));
}

void DHCPv6Client::put_option(std::vector<uint8_t> &buf, uint16_t code,
                               const uint8_t *data, uint16_t data_len) {
    put_u16(buf, code);
    put_u16(buf, data_len);
    buf.insert(buf.end(), data, data + data_len);
}

void DHCPv6Client::put_option(std::vector<uint8_t> &buf, uint16_t code,
                               const std::vector<uint8_t> &data) {
    if (data.size() > UINT16_MAX)
        throw std::runtime_error("DHCPv6 option data exceeds 65535 bytes");
    put_option(buf, code, data.data(), static_cast<uint16_t>(data.size()));
}

uint16_t DHCPv6Client::get_u16(const uint8_t *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

uint32_t DHCPv6Client::get_u32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

/* ===================================================================== */
/*  Construction / Destruction                                           */
/* ===================================================================== */

DHCPv6Client::DHCPv6Client(const std::string &iface, const uint8_t mac[6],
                           uint32_t iaid, int hint_len,
                           int timeout_s, int max_retrans)
    : iface_(iface), iaid_(iaid), hint_len_(hint_len),
      timeout_s_(timeout_s), max_retrans_(max_retrans) {

    if_index_ = netconfig::get_ifindex(iface);
    build_duid(mac);

    /* Create UDP socket for DHCPv6 */
    sock_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock_ < 0)
        throw std::runtime_error("socket(AF_INET6, SOCK_DGRAM) failed");

    /* Allow address reuse */
    int one = 1;
    setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    /* Bind to the WAN interface */
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    if (setsockopt(sock_, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
        LOG_WRN("SO_BINDTODEVICE failed (non-fatal): %s", strerror(errno));

    /* Set outgoing multicast interface */
    int idx = if_index_;
    setsockopt(sock_, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof(idx));

    /* Bind to client port */
    struct sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port   = htons(DHCP6_CLIENT_PORT);
    sa.sin6_addr   = in6addr_any;
    if (bind(sock_, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) < 0)
        throw std::runtime_error(
            std::string("bind(port 546) failed: ") + strerror(errno));

    LOG_INF("DHCPv6 client on %s (ifindex %d), IAID %u, hint /%d",
            iface_.c_str(), if_index_, iaid_, hint_len_);
}

DHCPv6Client::~DHCPv6Client() {
    if (sock_ >= 0) close(sock_);
}

/* ===================================================================== */
/*  DUID / Transaction ID                                                */
/* ===================================================================== */

void DHCPv6Client::build_duid(const uint8_t mac[6]) {
    /* DUID-LL: type 3, hardware type 1 (Ethernet), 6-byte address */
    client_duid_.clear();
    put_u16(client_duid_, 3);   /* DUID-LL */
    put_u16(client_duid_, 1);   /* Ethernet */
    client_duid_.insert(client_duid_.end(), mac, mac + 6);
}

void DHCPv6Client::new_xid() {
    /* 3 cryptographically random bytes */
    if (getrandom(xid_, sizeof(xid_), 0) != sizeof(xid_))
        throw std::runtime_error("getrandom() failed for transaction ID");
}

/* ===================================================================== */
/*  Message builders                                                     */
/* ===================================================================== */

/*
 * Common preamble: msg-type (1) + transaction-id (3).
 * All messages include: Client ID, Elapsed Time, IA_PD.
 * Request/Renew/Release also include Server ID.
 */

static void append_ia_pd_body(std::vector<uint8_t> &ia_pd,
                              uint32_t iaid,
                              int hint_len,
                              bool include_hint,
                              const DelegatedPrefix *existing) {
    DHCPv6Client::put_u32(ia_pd, iaid);
    DHCPv6Client::put_u32(ia_pd, 0);  /* T1 (let server decide) */
    DHCPv6Client::put_u32(ia_pd, 0);  /* T2 */

    if (include_hint || existing) {
        std::vector<uint8_t> sub;
        if (existing && existing->valid) {
            DHCPv6Client::put_u32(sub, existing->preferred_lt);
            DHCPv6Client::put_u32(sub, existing->valid_lt);
            sub.push_back(static_cast<uint8_t>(existing->prefix_len));
            sub.insert(sub.end(), existing->prefix.s6_addr,
                       existing->prefix.s6_addr + 16);
        } else {
            DHCPv6Client::put_u32(sub, 0);
            DHCPv6Client::put_u32(sub, 0);
            sub.push_back(static_cast<uint8_t>(hint_len));
            for (int i = 0; i < 16; ++i) sub.push_back(0);
        }
        DHCPv6Client::put_option(ia_pd, OPT_IAPREFIX, sub);
    }
}

std::vector<uint8_t> DHCPv6Client::build_solicit() {
    new_xid();
    std::vector<uint8_t> msg;

    msg.push_back(DHCP6_SOLICIT);
    msg.push_back(xid_[0]); msg.push_back(xid_[1]); msg.push_back(xid_[2]);

    /* Client ID */
    put_option(msg, OPT_CLIENTID, client_duid_);

    /* Elapsed Time = 0 */
    uint8_t et[2] = {0, 0};
    put_option(msg, OPT_ELAPSED_TIME, et, 2);

    /* IA_PD with prefix-length hint */
    std::vector<uint8_t> ia_pd;
    append_ia_pd_body(ia_pd, iaid_, hint_len_, true, nullptr);
    put_option(msg, OPT_IA_PD, ia_pd);

    /* Option Request: ask for IA_PD */
    uint8_t oro[2];
    oro[0] = static_cast<uint8_t>(OPT_IA_PD >> 8);
    oro[1] = static_cast<uint8_t>(OPT_IA_PD);
    put_option(msg, OPT_ORO, oro, 2);

    return msg;
}

std::vector<uint8_t> DHCPv6Client::build_request() {
    new_xid();
    std::vector<uint8_t> msg;

    msg.push_back(DHCP6_REQUEST);
    msg.push_back(xid_[0]); msg.push_back(xid_[1]); msg.push_back(xid_[2]);

    put_option(msg, OPT_CLIENTID, client_duid_);
    put_option(msg, OPT_SERVERID, server_duid_);

    uint8_t et[2] = {0, 0};
    put_option(msg, OPT_ELAPSED_TIME, et, 2);

    std::vector<uint8_t> ia_pd;
    append_ia_pd_body(ia_pd, iaid_, hint_len_, false, &dp_);
    put_option(msg, OPT_IA_PD, ia_pd);

    return msg;
}

std::vector<uint8_t> DHCPv6Client::build_renew() {
    new_xid();
    std::vector<uint8_t> msg;

    msg.push_back(DHCP6_RENEW);
    msg.push_back(xid_[0]); msg.push_back(xid_[1]); msg.push_back(xid_[2]);

    put_option(msg, OPT_CLIENTID, client_duid_);
    put_option(msg, OPT_SERVERID, server_duid_);

    uint8_t et[2] = {0, 0};
    put_option(msg, OPT_ELAPSED_TIME, et, 2);

    std::vector<uint8_t> ia_pd;
    append_ia_pd_body(ia_pd, iaid_, hint_len_, false, &dp_);
    put_option(msg, OPT_IA_PD, ia_pd);

    return msg;
}

std::vector<uint8_t> DHCPv6Client::build_rebind() {
    new_xid();
    std::vector<uint8_t> msg;

    msg.push_back(DHCP6_REBIND);
    msg.push_back(xid_[0]); msg.push_back(xid_[1]); msg.push_back(xid_[2]);

    put_option(msg, OPT_CLIENTID, client_duid_);
    /* No Server ID in Rebind */

    uint8_t et[2] = {0, 0};
    put_option(msg, OPT_ELAPSED_TIME, et, 2);

    std::vector<uint8_t> ia_pd;
    append_ia_pd_body(ia_pd, iaid_, hint_len_, false, &dp_);
    put_option(msg, OPT_IA_PD, ia_pd);

    return msg;
}

std::vector<uint8_t> DHCPv6Client::build_release() {
    new_xid();
    std::vector<uint8_t> msg;

    msg.push_back(DHCP6_RELEASE);
    msg.push_back(xid_[0]); msg.push_back(xid_[1]); msg.push_back(xid_[2]);

    put_option(msg, OPT_CLIENTID, client_duid_);
    put_option(msg, OPT_SERVERID, server_duid_);

    std::vector<uint8_t> ia_pd;
    append_ia_pd_body(ia_pd, iaid_, hint_len_, false, &dp_);
    put_option(msg, OPT_IA_PD, ia_pd);

    return msg;
}

/* ===================================================================== */
/*  Sending / receiving                                                  */
/* ===================================================================== */

static struct sockaddr_in6 make_mcast_dest(int if_index) {
    struct sockaddr_in6 sa{};
    sa.sin6_family   = AF_INET6;
    sa.sin6_port     = htons(DHCP6_SERVER_PORT);
    sa.sin6_scope_id = static_cast<uint32_t>(if_index);
    inet_pton(AF_INET6, DHCP6_MCAST, &sa.sin6_addr);
    return sa;
}

bool DHCPv6Client::send_and_wait(const std::vector<uint8_t> &msg,
                                  uint8_t expected_type) {
    auto dest = make_mcast_dest(if_index_);

    int timeout = timeout_s_;
    for (int attempt = 0; attempt < max_retrans_; ++attempt) {
        LOG_DBG("DHCPv6: sending type %d, attempt %d/%d (timeout %ds)",
                msg[0], attempt + 1, max_retrans_, timeout);

        ssize_t n = sendto(sock_, msg.data(), msg.size(), 0,
                           reinterpret_cast<struct sockaddr *>(&dest),
                           sizeof(dest));
        if (n < 0) {
            LOG_ERR("DHCPv6 sendto: %s", strerror(errno));
            return false;
        }

        /* Wait for a matching reply */
        struct pollfd pfd{};
        pfd.fd     = sock_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, timeout * 1000);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            uint8_t buf[2048];
            struct sockaddr_in6 src{};
            socklen_t srclen = sizeof(src);
            ssize_t rn = recvfrom(sock_, buf, sizeof(buf), 0,
                                  reinterpret_cast<struct sockaddr *>(&src),
                                  &srclen);
            if (rn > 4 && parse_message(buf, static_cast<size_t>(rn),
                                        expected_type)) {
                return true;
            }
            LOG_DBG("DHCPv6: received non-matching message, retrying");
        }

        /* Exponential backoff, capped at 120s */
        timeout = std::min(timeout * 2, 120);
    }

    LOG_ERR("DHCPv6: no reply after %d attempts", max_retrans_);
    return false;
}

/* ===================================================================== */
/*  Parsing                                                              */
/* ===================================================================== */

bool DHCPv6Client::parse_ia_pd(const uint8_t *data, size_t len) {
    if (len < 12) return false;

    /* IAID(4) + T1(4) + T2(4) */
    uint32_t iaid = get_u32(data);
    if (iaid != iaid_) {
        LOG_DBG("DHCPv6: IA_PD IAID mismatch (%u vs %u)", iaid, iaid_);
        return false;
    }

    dp_.t1 = get_u32(data + 4);
    dp_.t2 = get_u32(data + 8);

    /* Parse sub-options */
    size_t pos = 12;
    while (pos + 4 <= len) {
        uint16_t sub_code = get_u16(data + pos);
        uint16_t sub_len  = get_u16(data + pos + 2);
        pos += 4;
        if (pos + sub_len > len) break;

        if (sub_code == OPT_IAPREFIX && sub_len >= 25) {
            dp_.preferred_lt = get_u32(data + pos);
            dp_.valid_lt     = get_u32(data + pos + 4);
            dp_.prefix_len   = data[pos + 8];
            std::memcpy(&dp_.prefix, data + pos + 9, 16);
            dp_.valid = true;

            LOG_INF("DHCPv6: received prefix %s/%d "
                    "(preferred=%u valid=%u T1=%u T2=%u)",
                    netconfig::to_string(dp_.prefix).c_str(),
                    dp_.prefix_len, dp_.preferred_lt, dp_.valid_lt,
                    dp_.t1, dp_.t2);
        } else if (sub_code == OPT_STATUS_CODE && sub_len >= 2) {
            uint16_t status = get_u16(data + pos);
            if (status != 0) {
                std::string msg_text(
                    reinterpret_cast<const char *>(data + pos + 2),
                    sub_len - 2);
                /* Sanitise: replace non-printable bytes */
                for (auto &c : msg_text)
                    if (c < 0x20 || c > 0x7E) c = '?';
                LOG_ERR("DHCPv6: IA_PD status %u: %s",
                        status, msg_text.c_str());
                return false;
            }
        }
        pos += sub_len;
    }

    return dp_.valid;
}

bool DHCPv6Client::parse_message(const uint8_t *data, size_t len,
                                  uint8_t expected_type) {
    if (len < 4) return false;

    uint8_t msg_type = data[0];
    if (msg_type != expected_type) {
        LOG_DBG("DHCPv6: expected type %d, got %d", expected_type, msg_type);
        return false;
    }

    /* Verify transaction ID */
    if (data[1] != xid_[0] || data[2] != xid_[1] || data[3] != xid_[2]) {
        LOG_DBG("DHCPv6: transaction ID mismatch");
        return false;
    }

    /* Parse top-level options */
    bool got_ia_pd   = false;
    bool client_ok   = false;
    size_t pos = 4;

    while (pos + 4 <= len) {
        uint16_t opt_code = get_u16(data + pos);
        uint16_t opt_len  = get_u16(data + pos + 2);
        pos += 4;
        if (pos + opt_len > len) break;

        switch (opt_code) {
        case OPT_CLIENTID:
            /* Verify it matches our DUID */
            if (opt_len == client_duid_.size() &&
                std::memcmp(data + pos, client_duid_.data(), opt_len) == 0)
                client_ok = true;
            break;

        case OPT_SERVERID:
            server_duid_.assign(data + pos, data + pos + opt_len);
            break;

        case OPT_IA_PD:
            got_ia_pd = parse_ia_pd(data + pos, opt_len);
            break;

        case OPT_STATUS_CODE:
            if (opt_len >= 2) {
                uint16_t st = get_u16(data + pos);
                if (st != 0) {
                    std::string txt(
                        reinterpret_cast<const char *>(data + pos + 2),
                        opt_len - 2);
                    for (auto &c : txt)
                        if (c < 0x20 || c > 0x7E) c = '?';
                    LOG_ERR("DHCPv6: status %u: %s", st, txt.c_str());
                }
            }
            break;

        default:
            break;
        }

        pos += opt_len;
    }

    if (!client_ok)
        LOG_WRN("DHCPv6: Client DUID mismatch or missing in reply");

    return got_ia_pd;
}

/* ===================================================================== */
/*  Public API                                                           */
/* ===================================================================== */

bool DHCPv6Client::obtain_prefix() {
    LOG_INF("DHCPv6: starting Solicit/Request exchange on %s",
            iface_.c_str());

    /* Step 1: Solicit → Advertise */
    auto solicit = build_solicit();
    dp_.valid = false;

    if (!send_and_wait(solicit, DHCP6_ADVERTISE)) {
        LOG_ERR("DHCPv6: Solicit failed – no Advertise received");
        return false;
    }

    if (server_duid_.empty()) {
        LOG_ERR("DHCPv6: Advertise had no Server ID");
        return false;
    }

    LOG_INF("DHCPv6: Advertise received, proceeding to Request");

    /* Step 2: Request → Reply */
    auto request = build_request();

    if (!send_and_wait(request, DHCP6_REPLY)) {
        LOG_ERR("DHCPv6: Request failed – no Reply received");
        return false;
    }

    if (!dp_.valid) {
        LOG_ERR("DHCPv6: Reply did not contain a valid prefix");
        return false;
    }

    LOG_INF("DHCPv6: prefix delegation successful: %s/%d",
            netconfig::to_string(dp_.prefix).c_str(), dp_.prefix_len);
    return true;
}

void DHCPv6Client::send_renew() {
    LOG_INF("DHCPv6: sending Renew");
    auto msg  = build_renew();
    auto dest = make_mcast_dest(if_index_);    /* could unicast, but mcast works */
    if (sendto(sock_, msg.data(), msg.size(), 0,
               reinterpret_cast<struct sockaddr *>(&dest), sizeof(dest)) < 0)
        LOG_ERR("DHCPv6 Renew sendto: %s", strerror(errno));
}

void DHCPv6Client::send_rebind() {
    LOG_INF("DHCPv6: sending Rebind");
    auto msg  = build_rebind();
    auto dest = make_mcast_dest(if_index_);
    if (sendto(sock_, msg.data(), msg.size(), 0,
               reinterpret_cast<struct sockaddr *>(&dest), sizeof(dest)) < 0)
        LOG_ERR("DHCPv6 Rebind sendto: %s", strerror(errno));
}

void DHCPv6Client::send_release() {
    if (server_duid_.empty() || !dp_.valid) return;
    LOG_INF("DHCPv6: sending Release");
    auto msg  = build_release();
    auto dest = make_mcast_dest(if_index_);
    if (sendto(sock_, msg.data(), msg.size(), 0,
               reinterpret_cast<struct sockaddr *>(&dest), sizeof(dest)) < 0)
        LOG_ERR("DHCPv6 Release sendto: %s", strerror(errno));
}

bool DHCPv6Client::handle_reply() {
    uint8_t buf[2048];
    struct sockaddr_in6 src{};
    socklen_t srclen = sizeof(src);

    ssize_t n = recvfrom(sock_, buf, sizeof(buf), MSG_DONTWAIT,
                         reinterpret_cast<struct sockaddr *>(&src), &srclen);
    if (n <= 4) return false;

    DelegatedPrefix old = dp_;
    bool ok = parse_message(buf, static_cast<size_t>(n), DHCP6_REPLY);

    if (ok && old.valid) {
        /* Detect prefix change */
        if (std::memcmp(&old.prefix, &dp_.prefix, 16) != 0 ||
            old.prefix_len != dp_.prefix_len) {
            LOG_INF("DHCPv6: PREFIX CHANGED from %s/%d to %s/%d",
                    netconfig::to_string(old.prefix).c_str(), old.prefix_len,
                    netconfig::to_string(dp_.prefix).c_str(), dp_.prefix_len);
        }
    }

    return ok;
}
