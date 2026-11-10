# drop-ipv4-opt

Two stopgaps to mitigate [CVE-2026-98432](https://nvd.nist.gov/vuln/detail/cve-2026-98432),
a use-after-free in the kernel's TCP handshake handling of IPv4 options. On most
hosts the bug can only be triggered by a SYN that carries IP options (see the
NetLabel/CIPSO exception below), so the stopgaps drop IPv4 packets with options
before the TCP code of the kernel sees them.

A packet has IP options when its IHL (header length) field is greater than 5,
which means the IPv4 header is longer than 20 bytes.

The stopgaps are not a fix. The fix is a patched kernel. Use the stopgaps until
you can upgrade.

> [!WARNING]
> **This may not protect hosts using NetLabel/CIPSO** (SELinux or Smack with a
> `CIPSOV4` mapping). On those hosts the kernel can attach IP options itself, so
> the bug may be reachable with ordinary SYNs. A patched kernel is the more
> reliable fix there.
> `netlabelctl map list` can help tell whether a host uses CIPSO: entries of
> type `CIPSOV4` suggest it does.

## Use both stopgaps

Each stopgap covers traffic that the other stopgap does not cover well. Install
the two stopgaps together.

1. **The XDP program** drops packets at the network interface, before the
   kernel network stack does work on them. It is very fast, so it is the best
   tool for traffic from the network. But it only sees packets that come in
   through the interface that you attach it to.
2. **The nftables rules** drop packets in the kernel network stack. They cost
   more CPU time for each packet, but they see local traffic, container
   traffic, and tunneled traffic that the XDP program cannot see.

With the two stopgaps installed, the XDP program drops the traffic from the
network first. The nftables rules then only do work on the traffic that the XDP
program did not see.

| Traffic                                                        | XDP program | nftables rules |
| -------------------------------------------------------------- | ----------- | -------------- |
| Packets that come in through the attached interface            | Dropped     | Dropped        |
| Loopback traffic                                               | Not seen    | Dropped        |
| Packets that the host sends                                    | Not seen    | Dropped        |
| Packets that the host unwraps from a tunnel (VXLAN, GRE, …)    | Not seen    | Dropped        |
| Container traffic that the host receives or routes             | Not seen    | Dropped        |
| Traffic that stays in the network namespace of a container     | Not seen    | Not seen       |
| Bridge traffic that does not go through the nftables hooks     | Not seen    | Not seen       |

The last two rows are gaps that stay open. Only a patched kernel closes them.

## Stopgap 1: XDP for traffic from the network

### What it does

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

### Attach to an interface

Replace `eth0` with your interface name (see `ip link`). If the host has more
than one interface that faces the network, attach the program to each one.

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

## Stopgap 2: nftables for local, container, and tunneled traffic

### What it does

The rules in [`nft/drop_ipv4_options.nft`](nft/drop_ipv4_options.nft) drop each
IPv4 packet with options on three paths of the host:

| Path    | Traffic                                                             |
| ------- | ------------------------------------------------------------------- |
| Input   | Packets for the host, which includes loopback and unwrapped packets |
| Forward | Packets that the host routes, such as container traffic             |
| Output  | Packets that the host sends                                         |

The rules go into a table of their own, `inet drop_ipv4_options`. They do not
change your other nftables rules.

### Requirements

`nftables` (for the `nft` command). There is nothing to build.

### Load the rules

```sh
sudo nft -f nft/drop_ipv4_options.nft
```

You can load the file again. The second load replaces the rules and does not
add them again.

### Check that the rules are loaded

```sh
sudo nft list table inet drop_ipv4_options
```

The output also shows the number of packets that each rule dropped.

### Keep the rules after a restart

The rules do not stay after a restart. To keep them, copy the file to a
location that your distribution loads at startup. For example, on Debian and
Ubuntu, add an `include` line for the file to `/etc/nftables.conf` and enable
`nftables.service`.

### Remove the rules

```sh
sudo nft delete table inet drop_ipv4_options
```

## Test

Test each stopgap with a ping that carries the Record Route option.

To test the XDP program, send the ping from another host:

```sh
ping -R <target-ip>
```

To test the nftables rules, send the ping on the host itself:

```sh
ping -R 127.0.0.1
```

With the stopgap in place, these pings get no reply. A normal ping without
`-R` still works.

## Limits

The two stopgaps together do not close these gaps:

- **Other network namespaces.** Neither stopgap sees traffic that stays in a
  different network namespace, such as loopback traffic in a container.
- **Bridge traffic.** Neither stopgap sees bridge traffic that does not go
  through the nftables hooks, such as traffic between two containers on one
  bridge.
- **NetLabel/CIPSO.** On hosts that use NetLabel/CIPSO, the kernel attaches the
  option itself, so the stopgaps do not stop the bug. The nftables output rule
  also drops the labeled packets that the host sends.

Upgrade to a patched kernel to close these gaps.

## License

MIT. See [LICENSE](LICENSE).
