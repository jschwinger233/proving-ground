// +build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u64);
} stacks SEC(".maps");


SEC("fentry/tc")
int BPF_PROG(trace_on_entry, struct __sk_buff *skb)
{
	__u64 stackid = bpf_get_stackid(ctx, &stacks, 0);
	bpf_printk("stackid: %d %llx\n", stackid, skb);
	return 0;
}

char _license[] SEC("license") = "GPL";

