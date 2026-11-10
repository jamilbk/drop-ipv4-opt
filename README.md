# drop-ipv4-opt

Two stopgaps for [CVE-2026-98432](https://nvd.nist.gov/vuln/detail/cve-2026-98432),
a use-after-free in the kernel's TCP handshake handling of IPv4 options. On most
hosts the bug can only be triggered by a SYN that carries IP options (see the
NetLabel/CIPSO exception below), and practically nothing legitimate needs IP
options, so both stopgaps simply drop any IPv4 packet that has them.

Use both:

1. **XDP** for fast ingress filtering. It drops packets at the NIC before
   they're passed up the network stack, but it only sees what arrives on the
   interface it's attached to.
2. **nftables** for everything XDP can't see: loopback, traffic the host sends,
   tunneled traffic after it's unwrapped, and container traffic routed through
   the host. It's a bit more expensive per packet, which is why XDP goes first.

Neither is a fix - upgrade to a patched kernel as soon as you can.

A packet has IP options when its IHL (header length) field is greater than 5,
which means the IPv4 header is longer than 20 bytes.

> [!WARNING]
> **This may not protect hosts using NetLabel/CIPSO** (SELinux or Smack with a
> `CIPSOV4` mapping). On those hosts the kernel can attach IP options itself, so
> the bug may be reachable with ordinary SYNs. A patched kernel is the more
> reliable fix there.
> `netlabelctl map list` can help tell whether a host uses CIPSO: entries of
> type `CIPSOV4` suggest it does.

## Stopgap 1: XDP

| Packet                       | Action     |
| ---------------------------- | ---------- |
| IPv4 with options (IHL > 5)  | `XDP_DROP` |
| IPv4 without options         | `XDP_PASS` |
| Anything else (IPv6, ARP, …) | `XDP_PASS` |
| Truncated / malformed header | `XDP_PASS` |

VLAN-tagged frames are handled too: the program skips up to two VLAN tags
(802.1Q and 802.1ad/QinQ) before it checks for IPv4. Frames with more than two
tags are passed through.

### Requirements

On a Linux host:

- `clang` and `llvm`
- `libbpf-dev` (for `bpf/bpf_helpers.h`)
- Kernel headers (`linux-headers-$(uname -r)` or `linux-libc-dev`)
- `iproute2` (for `ip link`), and optionally `bpftool`

Debian / Ubuntu:

```sh
sudo apt install clang llvm libbpf-dev linux-libc-dev iproute2 bpftool
```

Fedora:

```sh
sudo dnf install clang llvm libbpf-devel kernel-headers iproute bpftool
```

### Build

```sh
make
```

This produces `drop_ipv4_opt.o`.

### Attach

Replace `eth0` with your interface name (see `ip link`). Repeat for every
network-facing interface.

Native (driver) mode, which is the fastest:

```sh
sudo ip link set dev eth0 xdpdrv obj drop_ipv4_opt.o sec xdp
```

Generic (SKB) mode, which works on any interface but is slower:

```sh
sudo ip link set dev eth0 xdpgeneric obj drop_ipv4_opt.o sec xdp
```

Let the kernel pick the mode (native if supported, else generic):

```sh
sudo ip link set dev eth0 xdp obj drop_ipv4_opt.o sec xdp
```

### Check that it is attached

```sh
ip link show dev eth0          # look for "xdp" / "prog/xdp id N"
sudo bpftool net show dev eth0
```

### Detach

```sh
sudo ip link set dev eth0 xdp off
```

Use `xdpdrv off` or `xdpgeneric off` if you attached in that specific mode.

## Stopgap 2: nftables

[`nft/drop_ipv4_options.nft`](nft/drop_ipv4_options.nft) drops IPv4 packets
with options on the host's input, forward, and output hooks. The rules live in
their own table (`inet drop_ipv4_options`), so they won't touch your existing
ruleset, and the file is safe to load more than once.

### Load

```sh
sudo nft -f nft/drop_ipv4_options.nft
```

This doesn't survive a reboot. To make it permanent, `include` the file from
wherever your distro loads nftables rules at boot (`/etc/nftables.conf` on
Debian / Ubuntu, with `nftables.service` enabled).

### Check that it is loaded

```sh
sudo nft list table inet drop_ipv4_options
```

Each rule has a counter, so this also shows how many packets were dropped.

### Remove

```sh
sudo nft delete table inet drop_ipv4_options
```

## Test

Send a packet with an IP option, e.g. with the Record Route option. From
another host to test XDP:

```sh
ping -R <target-ip>
```

And on the host itself to test nftables:

```sh
ping -R 127.0.0.1
```

With the stopgaps in place, these pings get no reply. A normal `ping` still
works.

## What this doesn't cover

Even with both stopgaps, a few gaps remain:

- Traffic confined to another network namespace, such as loopback inside a
  container.
- Bridge traffic that bypasses the nftables hooks, such as two containers
  talking over the same bridge.
- NetLabel/CIPSO hosts, per the warning above. Note the nftables output rule
  will also drop the host's own labeled packets.

Only a patched kernel closes these.

## License

MIT. See [LICENSE](LICENSE).
