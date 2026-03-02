# slaacbot

A self-contained Linux daemon that handles IPv6 prefix delegation and SLAAC
without depending on systemd, dhcpcd, radvd, or any other high-level service.

## What it does

1. **DHCPv6-PD** – Requests a /56 (configurable) prefix from your ISP on the
   WAN interface, building DHCPv6 packets from scratch.
2. **Prefix carving** – Splits the delegated /56 into /64 subnets.
3. **LAN configuration** – Assigns an address from the selected /64 to the LAN
   interface and installs the corresponding route via the `ip` tool.
4. **SLAAC** – Sends periodic ICMPv6 Router Advertisements on the LAN so
   clients can auto-configure their IPv6 addresses.
5. **Prefix change handling** – When the ISP renumbers, slaacbot tears down the
   old prefix (deprecates it with lifetime-0 RAs), configures the new one, and
   notifies all LAN clients immediately.
6. **Clean shutdown** – On SIGINT/SIGTERM the daemon depreciates the prefix,
   releases the DHCPv6 lease, and removes every address and route it added.

## Building

```
make            # produces ./slaacbot
make install    # copies to /usr/local/sbin/
```

Requires **g++** with C++17 support.  No external libraries.

## Configuration

Copy `config.ini` to `/etc/slaacbot.conf` (or pass `-c <path>`):

```ini
[wan]
interface = eth0          # ISP-facing interface

[lan]
interface = eth1          # client-facing interface
subnet_index = 0          # which /64 of the delegated prefix (0-255)

[dhcpv6]
prefix_length = 56        # prefix length to request
iaid = 1
retransmit_timeout = 5
max_retransmit = 10

[ra]
interval = 30             # seconds between unsolicited RAs
router_lifetime = 1800
valid_lifetime = 86400
preferred_lifetime = 14400
mtu = 0                   # 0 = omit MTU option
hop_limit = 64
```

## Running

```
sudo ./slaacbot -c config.ini       # foreground, default log level
sudo ./slaacbot -c config.ini -v    # verbose (debug logging)
sudo ./slaacbot -c config.ini -d    # daemonise
```

Root privileges are required (raw sockets, sysctl, `ip` commands).

## Architecture

```
src/
  main.cpp       – Daemon lifecycle & poll()-based event loop
  config.h/cpp   – INI file parser
  netconfig.h/cpp– Interface, address, route management via `ip`
  dhcpv6.h/cpp   – DHCPv6-PD client (hand-built packets)
  icmpv6.h/cpp   – ICMPv6 Router Advertisement / Solicitation
  log.h          – Lightweight timestamped logging macros
```
