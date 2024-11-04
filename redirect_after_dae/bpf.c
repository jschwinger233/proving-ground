#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc/redirect")
int tc_redirect(struct __sk_buff *skb) {
	void *data = (void*)(long)skb->data;
	void *data_end = (void*)(long)skb->data_end;
	struct iphdr *ip = (struct iphdr *)(data + 14);
	if (ip + 1 <= (struct iphdr *)data_end) {
		if (ip->daddr == 0x01010101) {
			ip->addr = 0x01010102;
			return bpf_redirect(REDIRECT_IFINDEX, 0);
		}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
