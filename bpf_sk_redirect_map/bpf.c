// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} sk_map SEC(".maps");

SEC("tc/redirect")
int tc_redirect(struct __sk_buff *skb) {
	return bpf_sk_redirect_map(skb, &sk_map, 0, BPF_F_INGRESS);
}
