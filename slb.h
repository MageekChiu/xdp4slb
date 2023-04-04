#include <stddef.h>
// https://github.com/cilium/cilium/issues/368
// dnf install glibc-devel.i686
// #include <stdio.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_packet.h>
#include <linux/types.h>
// #include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#define ETH_P_IP	0x0800		
#define ETH_ALEN 6

#define TCP_MAX_BITS 1480

#undef AF_INET
#define AF_INET 2

// convenient for debugging
// #define NUM_BACKENDS 1
#define NUM_BACKENDS 2
typedef struct host_meta {
    char *ip;
    __u32 ip_int;
    unsigned char mac_addr[ETH_ALEN];
    __u16 port;
} hm;

#define MAX_U_32_INT 4294967295.0
#define NAT_PORT_MIN 30100
#define NAT_PORT_MAX 60900
#define NAT_PORT_RANGE (NAT_PORT_MAX - NAT_PORT_MIN)

__u32 map_flags = BPF_ANY;

struct conntrack_entry {
    __u32 ip;
    __u16 port;
} __attribute__((packed));
typedef struct conntrack_entry ce;

#define ARP_MAP_SIZE 1024
#define SNAT_MAP_SIZE 1024
#define DNAT_MAP_SIZE 1024
#define BACKEND_MAP_SIZE 1024


enum LB_ALG{
    random, round_robin
};

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __attribute__((always_inline)) __u16
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

static __attribute__((always_inline)) __u16
iph_csum(struct iphdr *iph){
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __attribute__((always_inline)) __u16 
ipv4_l4_csum(void* data_start, __u32 data_size, struct iphdr* iph,void *data_end) {
    __u64 csum_buffer = 0;
    __u16 *buf = (void *)data_start;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u32)iph->protocol << 8;
    csum_buffer += data_size;

    // Compute checksum on udp header + payload
    for (int i = 0; i < TCP_MAX_BITS; i += 2) {
        if ((void *)(buf + 1) > data_end) {
            break;
        }
        csum_buffer += *buf;
        buf++;
    }
    if ((void *)buf + 1 <= data_end) {
    // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    return csum_fold_helper(csum_buffer);
}
