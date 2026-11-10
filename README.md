# drop-ipv4-opt

A tiny XDP program to mitigate [CVE-2026-98432](https://nvd.nist.gov/vuln/detail/cve-2026-98432),
a use-after-free in the kernel's TCP handshake handling of IPv4 options. On most
hosts the bug can only be triggered by an incoming SYN that carries IP options
(see the NetLabel/CIPSO exception below), so this program drops IPv4 packets
with options before they're passed up the network stack to the kernel.

A packet has IP options when its IHL (header length) field is greater than 5,
which means the IPv4 header is longer than 20 bytes.

> [!WARNING]
> **This may not protect hosts using NetLabel/CIPSO** (SELinux or Smack with a
> `CIPSOV4` mapping). On those hosts the kernel can attach IP options itself, so
> the bug may be reachable with ordinary SYNs. A patched kernel is the more
> reliable fix there.
> `netlabelctl map list` can help tell whether a host uses CIPSO: entries of
> type `CIPSOV4` suggest it does.

## What it does

| Packet                       | Action     |
| ---------------------------- | ---------- |
| IPv4 with options (IHL > 5)  | `XDP_DROP` |
| IPv4 without options         | `XDP_PASS` |
| Anything else (IPv6, ARP, …) | `XDP_PASS` |
| Truncated / malformed header | `XDP_PASS` |

VLAN-tagged frames are handled too: the program skips up to two VLAN tags
(802.1Q and 802.1ad/QinQ) before it checks for IPv4. Frames with more than two
tags are passed through.

## Requirements

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

## Build

```sh
make
```

This produces `drop_ipv4_opt.o`.

## Attach to an interface

Replace `eth0` with your interface name (see `ip link`).

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

## Check that it is attached

```sh
ip link show dev eth0          # look for "xdp" / "prog/xdp id N"
sudo bpftool net show dev eth0
```

## Detach

```sh
sudo ip link set dev eth0 xdp off
```

Use `xdpdrv off` or `xdpgeneric off` if you attached in that specific mode.

## Test

From another host, send a packet with an IP option, e.g. with the Record
Route option:

```sh
ping -R <target-ip>
```

With the program attached, these pings get no reply. A normal `ping
<target-ip>` still works.

## Secondary stopgap: nftables

The XDP program only sees the packets that come in through the interface it is
attached to. It does not see these packets:

- Loopback traffic
- Traffic that the host sends
- Traffic that the host unwraps from a tunnel, such as VXLAN, GRE, or WireGuard

To drop these packets too, load the nftables rules in
[`nft/drop_ipv4_options.nft`](nft/drop_ipv4_options.nft). The rules drop each
IPv4 packet with options on the input, forward, and output paths of the host.
The rules cost more CPU time for each packet than the XDP program, so use them
together with the XDP program.

Load the rules:

```sh
sudo nft -f nft/drop_ipv4_options.nft
```

The rules go into a table of their own, `inet drop_ipv4_options`. They do not
change your other nftables rules.

Show the rules and the number of packets that each rule dropped:

```sh
sudo nft list table inet drop_ipv4_options
```

Remove the rules:

```sh
sudo nft delete table inet drop_ipv4_options
```

The rules do not stay after a restart. To keep them, copy the file to a
location that your distribution loads at startup. For example, on Debian and
Ubuntu, add an `include` line for the file to `/etc/nftables.conf` and enable
`nftables.service`.

The nftables rules have these limits:

- They do not see traffic that stays in a different network namespace, such as
  loopback traffic in a container.
- They do not see bridge traffic that does not go through these hooks.
- They do not protect hosts that use NetLabel/CIPSO. On those hosts, the output
  rule also drops the labeled packets that the host sends.

## License

MIT. See [LICENSE](LICENSE).
