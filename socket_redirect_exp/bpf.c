// +build ignore

#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "socket_defs.h"

struct config {
	char comm[16];
};

static volatile const struct config CFG = {};

struct tuple {
	__be32 saddr;
	__be32 daddr;
	__be32 sport;
	__be32 dport;
};

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key, struct tuple);
	__type(value, __u64);
	__uint(max_entries, 65535);
} fast_sock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tuple);
	__type(value, bool);
	__uint(max_entries, 256);
} local_sock SEC(".maps");

SEC("sockops")
int tcp_sockops(struct bpf_sock_ops *skops)
{
	// only interested in ipv4
	if (skops->family != AF_INET)
		return 0;

	char comm[16];
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	BPF_CORE_READ_STR_INTO(&comm, task, comm);
	if (bpf_strncmp(comm, 16, (void *)CFG.comm) != 0)
		return 0;

	struct tuple tuple = {};
	tuple.saddr = skops->local_ip4;
	tuple.daddr = skops->remote_ip4;
	tuple.sport = bpf_htonl(skops->local_port) >> 16;
	tuple.dport = skops->remote_port >> 16;

	switch (skops->op) {

	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY);
		break;

	default:
		break;
	}

	return 0;
}

SEC("sk_msg/fast_redirect")
int sk_msg_fast_redirect(struct sk_msg_md *msg)
{
	struct tuple rev_tuple = {};
	rev_tuple.saddr = msg->remote_ip4;
	rev_tuple.daddr = msg->local_ip4;
	rev_tuple.sport = msg->remote_port >> 16;
	rev_tuple.dport = bpf_htonl(msg->local_port) >> 16;

	bpf_printk("tcp fast redirect: %pI4:%lu -> %pI4:%lu",
		&rev_tuple.daddr, bpf_ntohs(rev_tuple.dport),
		&rev_tuple.saddr, bpf_ntohs(rev_tuple.sport));
	return bpf_msg_redirect_hash(msg, &fast_sock, &rev_tuple, BPF_F_INGRESS);
}

SEC("license") const char __license[] = "Dual BSD/GPL";
