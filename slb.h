#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TCP_MAX_BITS 1400

#undef AF_INET
#define AF_INET 2

#define NUM_BACKENDS 2
typedef struct host_meta {
    char *ip;
    __u32 ip_int;
    __u16 port;
} hm;

#define NAT_PORT_MIN 30100
#define NAT_PORT_MAX 60900

__u32 map_flags = BPF_ANY;

struct conntrack_entry {
    __u32 ip;
    __u16 port;
} __attribute__((packed));
typedef struct conntrack_entry ce;

#define SNAT_MAP_SIZE 1024
#define DNAT_MAP_SIZE 1024
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SNAT_MAP_SIZE);
    __type(key, ce);
    __type(value, ce);
} snat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, DNAT_MAP_SIZE);
    __type(key, ce);
    __type(value, ce);
} dnat_map SEC(".maps");

enum LB_ALG{
    random, round_robin
};

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph){
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline __u16 
ipv4_l4_csum(void* data_start, __u32 data_size, struct iphdr* iph) {
    __u32 tmp = 0;
    __u64* csum = 0;
    *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
    *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
    tmp = __builtin_bswap32((__u32)(iph->protocol));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    tmp = __builtin_bswap32((__u32)(data_size));
    *csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    return csum_fold_helper(*csum);
}
