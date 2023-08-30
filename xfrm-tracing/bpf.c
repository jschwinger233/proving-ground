// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

extern struct linux_xfrm_mib xfrm_statistics __ksym; /* struct type global var. */

const static bool TRUE = true;


SEC("kprobe/native_netif_rx_internal")
int native_netif_rx_internal(struct pt_regs *ctx)
{
	return 0;
}

SEC("kprobe/veth_netif_rx_internal")
int veth_netif_rx_internal(struct pt_regs *ctx)
{
	return 0;
}

SEC("kprobe/kfree_skbmem")
int on_kfree_skbmem(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->di;
    struct net *net = BPF_CORE_READ(skb, dev, nd_net).net;
    xfrm_statistics = *BPF_CORE_READ(net, mib).xfrm_statistics;

    __u64 xfrm_errors[29];
    for (int i=0; i<12; i++) {
	    struct linux_xfrm_mib *per_cpu_xfrm_mib = bpf_per_cpu_ptr(&xfrm_statistics, i);
	    if (!per_cpu_xfrm_mib)
		    break;

	    for (int j=0; j<29; j++)
		    xfrm_errors[j] += per_cpu_xfrm_mib->mibs[j];
    }

    for (int i=0; i<29; i++) {
	    if (xfrm_errors[i] > 0) {
		    bpf_printk("xfrm_errors[%d] = %lld\n", i, xfrm_errors[i]);
	    }
    }
    return 0;
}
