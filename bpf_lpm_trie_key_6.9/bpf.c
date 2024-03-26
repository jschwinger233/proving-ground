// +build ignore

#include "vmlinux.h"

#include "bpf_core_read.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

#define __maybe_unused		__attribute__((__unused__))

#define TC_ACT_OK 0
#define IPV6_BYTE_LENGTH 16

struct lpm_key {
	struct bpf_lpm_trie_key trie_key;
	__be32 data[4];
};

SEC("tc/ingress")
int ingress(struct __sk_buff *skb) {
	struct lpm_key lpm_key_instance;
	lpm_key_instance.trie_key.prefixlen = IPV6_BYTE_LENGTH * 8;
	//struct lpm_key __maybe_unused lpm_key_instance = {
	//	.trie_key = { IPV6_BYTE_LENGTH * 8, {} },
	//};
	return TC_ACT_OK;
}

SEC("license") const char __license[] = "Dual BSD/GPL";
