// SPDX-License-Identifier: MIT
//
// XDP program that drops IPv4 packets carrying IP options (IHL > 5)
// and passes everything else up the stack.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Max number of stacked VLAN tags to skip (802.1Q + 802.1ad/QinQ).
#define VLAN_MAX_DEPTH 2

// Defined here because <linux/if_vlan.h> is not exported to userspace.
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int drop_ipv4_opt(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__be16 proto = eth->h_proto;
	void *cur = eth + 1;

	// Skip any VLAN tags so tagged IPv4 traffic is filtered too.
#pragma unroll
	for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (proto != bpf_htons(ETH_P_8021Q) &&
		    proto != bpf_htons(ETH_P_8021AD))
			break;

		struct vlan_hdr *vh = cur;
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;

		proto = vh->h_vlan_encapsulated_proto;
		cur = vh + 1;
	}

	if (proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = cur;
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	// IHL is the header length in 32-bit words. 5 words (20 bytes) means
	// no options. Anything larger means the packet carries IP options.
	if (iph->ihl > 5)
		return XDP_DROP;

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
