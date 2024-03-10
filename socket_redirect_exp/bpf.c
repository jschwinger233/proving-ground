// +build ignore

#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

static const bool TRUE = true;

struct bpf_param {
  __u32 tproxy_pid;
};

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
	struct tuple tuple = {};
	tuple.saddr = skops->local_ip4;
	tuple.daddr = skops->remote_ip4;
	tuple.sport = skops->local_port;
	tuple.dport = bpf_ntohl(skops->remote_port);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 task_pid = BPF_CORE_READ(task, pid);
	switch (skops->op) {

	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // proxy
		// lookup some map to make sure it's proxy connection
		if (task_pid) { // then it's a local connection!
			struct tuple rev_tuple = {};
			rev_tuple.saddr = tuple.daddr;
			rev_tuple.daddr = tuple.saddr;
			rev_tuple.sport = tuple.dport;
			rev_tuple.dport = tuple.sport;
			if (bpf_map_lookup_elem(&local_sock, &rev_tuple)) {
				bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY);
			} else {
				bpf_map_delete_elem(&fast_sock, &rev_tuple);
			}
		}
		break;

	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: // client
		if (task_pid) { // then it's a local connection
			bpf_sock_hash_update(skops, &fast_sock, &tuple, BPF_ANY);
			bpf_map_update_elem(&local_sock, &tuple, &TRUE, BPF_ANY);
		}
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
	rev_tuple.sport = bpf_ntohl(msg->remote_port);
	rev_tuple.dport = msg->local_port;

	bpf_msg_redirect_hash(msg, &fast_sock, &rev_tuple, BPF_F_INGRESS);
	return SK_PASS;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
