// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

SEC("fentry/tc")
int BPF_PROG(trace_on_entry, struct __sk_buff *skb)
{
	bpf_printk("fentry %llx\n", skb);
	return 0;
}

char _license[] SEC("license") = "GPL";

