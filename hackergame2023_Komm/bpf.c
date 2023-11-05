#define ETH_P_IP              0x800

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "endian.h"

#define OFF_IPV4_CSUM (offsetof(struct iphdr, check) + sizeof(struct ethhdr))

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc/add_ip_option")
int tc_add_ip_option(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
	return 0;

    bpf_skb_adjust_room(skb, 20, BPF_ADJ_ROOM_NET, 0);

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    if (data + 34 > data_end)
	    return 0;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
	return 0;

    ip->ihl += 5;
    __u16 old_tot_len = ip->tot_len;
    ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + 20);

    __u8 *ip_opt = (void *)ip + sizeof(*ip);
    if ((void *)ip_opt + 20 > data_end)
	return 0;

    __u8 opt[20] = {0x44, 20, '.', '.', 'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P'};
    __builtin_memcpy(ip_opt, &opt, 20);

    bpf_l3_csum_replace(skb, OFF_IPV4_CSUM, 0, ip->tot_len - old_tot_len, 2);
    bpf_l3_csum_replace(skb, OFF_IPV4_CSUM, 0, 5, 2);
    bpf_l3_csum_replace(skb, OFF_IPV4_CSUM, 0, *(__u32*)(&opt[0]), 4);
    bpf_l3_csum_replace(skb, OFF_IPV4_CSUM, 0, *(__u32*)(&opt[4]), 4);
    bpf_l3_csum_replace(skb, OFF_IPV4_CSUM, 0, *(__u32*)(&opt[8]), 4);
    bpf_l3_csum_replace(skb, OFF_IPV4_CSUM, 0, *(__u32*)(&opt[12]), 4);
    return 0;
}

SEC("tc/change_tcp_reserved")
int tc_change_tcp_reserved(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
	return 0;

    struct iphdr *ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end || ip->protocol != IPPROTO_TCP)
	return 0;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
	return 0;

    tcp->res1 = 1;
    return 0;
}

char _license[] SEC("license") = "GPL";
