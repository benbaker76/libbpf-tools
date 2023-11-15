//go:build ignore
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Ben Baker

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

#define BPF_MAP_TYPE_SOCKMAP    15
#define ETH_P_IPV4	            0x0800

struct event {
    __u8 comm[16];
    __u32 pid;
    __u32 uid;
    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
};

struct event *unused_event __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 2);
} sock_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb)
{
    u32 data_offset = offsetof(struct __sk_buff, data);
    u32 protocol = bpf_htons(skb->protocol);

    if (protocol != ETH_P_IPV4) {
        bpf_printk("Not IPV4!\n");
        return 0;
    }

	struct event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e) {
		return 0;
	}

    struct task_struct *group_leader = (struct task_struct *)bpf_get_current_task_btf()->group_leader;

    bpf_probe_read_kernel(&e->comm, sizeof(e->comm), group_leader->comm);

    e->pid = bpf_htonl(group_leader->pid);
    e->uid = bpf_htonl(group_leader->cred->uid.val);

	e->saddr = skb->local_ip4;
	e->daddr = skb->remote_ip4;
	e->sport = bpf_htons(skb->local_port);
	e->dport = bpf_htons(skb->remote_port);

    bpf_ringbuf_submit(e, 0);

    return skb->len;
}

SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb)
{
    return SK_DROP;
}

char _license[] SEC("license") = "GPL";