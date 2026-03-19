/*
 * dhcpv6.h - Minimal DHCPv6 Prefix-Delegation client.
 *
 * Builds DHCPv6 packets from scratch (Solicit, Request, Renew, Rebind,
 * Release) and parses replies to extract the delegated prefix.
 * Uses a UDP socket on port 546 (client) → 547 (server).
 */
#pragma once

#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <vector>

/* ---- DHCPv6 message types ---------------------------------------------- */

enum DHCPv6Msg : uint8_t {
    DHCP6_SOLICIT     = 1,
    DHCP6_ADVERTISE   = 2,
    DHCP6_REQUEST     = 3,
    DHCP6_CONFIRM     = 4,
    DHCP6_RENEW       = 5,
    DHCP6_REBIND      = 6,
    DHCP6_REPLY       = 7,
    DHCP6_RELEASE     = 8,
    DHCP6_DECLINE     = 9,
    DHCP6_RECONFIGURE = 10,
    DHCP6_INFO_REQ    = 11,
};

/* ---- DHCPv6 option codes ----------------------------------------------- */

enum DHCPv6Opt : uint16_t {
    OPT_CLIENTID     = 1,
    OPT_SERVERID     = 2,
    OPT_IA_NA        = 3,
    OPT_IA_TA        = 4,
    OPT_IAADDR       = 5,
    OPT_ORO          = 6,
    OPT_PREFERENCE   = 7,
    OPT_ELAPSED_TIME = 8,
    OPT_STATUS_CODE  = 13,
    OPT_RAPID_COMMIT = 14,
    OPT_IA_PD        = 25,
    OPT_IAPREFIX     = 26,
};

/* ---- Delegated-prefix result ------------------------------------------ */

struct DelegatedPrefix {
    struct in6_addr prefix;
    int             prefix_len   = 0;
    uint32_t        preferred_lt = 0;
    uint32_t        valid_lt     = 0;
    uint32_t        t1           = 0;
    uint32_t        t2           = 0;
    bool            valid        = false;
};

/* ---- DHCPv6-PD client class ------------------------------------------- */

class DHCPv6Client {
public:
    /**
     * @param iface       WAN interface name
     * @param mac         6-byte MAC of the WAN interface
     * @param iaid        Identity-Association ID
     * @param hint_len    Requested prefix length (e.g. 56)
     * @param timeout_s   Retransmit timeout in seconds
     * @param max_retrans Maximum retransmit attempts
     */
    DHCPv6Client(const std::string &iface, const uint8_t mac[6],
                 uint32_t iaid, int hint_len,
                 int timeout_s, int max_retrans);
    ~DHCPv6Client();

    /* Non-copyable */
    DHCPv6Client(const DHCPv6Client &)            = delete;
    DHCPv6Client &operator=(const DHCPv6Client &) = delete;

    /**
     * Perform the full Solicit → Advertise → Request → Reply exchange.
     * Blocks until a prefix is obtained or all retries are exhausted.
     * Returns true on success (result available via prefix()).
     */
    bool obtain_prefix();

    /**
     * Send a Renew message (unicast to server that gave us the lease).
     * The caller should watch fd() for the Reply.
     */
    void send_renew();

    /**
     * Send a Rebind message (multicast, any server).
     */
    void send_rebind();

    /**
     * Send a Release message.
     */
    void send_release();

    /**
     * Process a received DHCPv6 message on the socket.
     * Returns true if the delegated prefix was updated.
     */
    bool handle_reply();

    /** Socket file descriptor (for poll/select). */
    int fd() const { return sock_; }

    /** Most recent delegated prefix information. */
    const DelegatedPrefix &prefix() const { return dp_; }

private:
    /* Socket */
    int         sock_ = -1;
    std::string iface_;
    int         if_index_;

    /* Configuration */
    uint32_t    iaid_;
    int         hint_len_;
    int         timeout_s_;
    int         max_retrans_;

    /* DUID-LL  (Type 3, HW type 1 = Ethernet, 6-byte MAC) */
    std::vector<uint8_t> client_duid_;

    /* Server DUID learned from Advertise */
    std::vector<uint8_t> server_duid_;

    /* Transaction ID for the current exchange (3 bytes) */
    uint8_t     xid_[3]{};

    /* Delegated prefix result */
    DelegatedPrefix dp_{};

    /* ---- internal helpers --------------------------------------------- */

    void new_xid();
    void build_duid(const uint8_t mac[6]);

    std::vector<uint8_t> build_solicit();
    std::vector<uint8_t> build_request();
    std::vector<uint8_t> build_renew();
    std::vector<uint8_t> build_rebind();
    std::vector<uint8_t> build_release();

    bool send_and_wait(const std::vector<uint8_t> &msg,
                       uint8_t expected_type);

    bool parse_message(const uint8_t *data, size_t len, uint8_t expected_type);
    bool parse_ia_pd(const uint8_t *data, size_t len);
    /* Append helpers (network byte order) */
public:
    static void put_u16(std::vector<uint8_t> &buf, uint16_t v);
    static void put_u32(std::vector<uint8_t> &buf, uint32_t v);
    static void put_option(std::vector<uint8_t> &buf, uint16_t code,
                           const uint8_t *data, uint16_t data_len);
    static void put_option(std::vector<uint8_t> &buf, uint16_t code,
                           const std::vector<uint8_t> &data);

    /* Read helpers */
    static uint16_t get_u16(const uint8_t *p);
    static uint32_t get_u32(const uint8_t *p);

private:
};
