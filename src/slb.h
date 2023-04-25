#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, c, n) __builtin_memset(dest, c, n) 
#endif


#define ETH_P_IP	0x0800		
#define ETH_ALEN 6
#undef AF_INET
#define AF_INET 2
#undef AF_INET6
#define AF_INET6 10
#define TCP_MAX_BITS 1480
#define IP_STRING_LEN 16


#define MAX_CONNTRACK 4096

#define MAX_BACKEND 8

enum LB_ALG{
    lb_random = 1, 
    lb_round_robin = 2, 
    lb_n_hash = 3,
};

enum clear_mode{
    just_local = 1, 
    group_cast = 2, 
    broad_cast = 3,
};

typedef unsigned int __u32;
typedef short unsigned int __u16;
typedef unsigned char __u8;

struct host_meta {
    // with *ip i have to copy myself, with array simple asignment wiil do copying for me
    char *ip;
    // __u8 ip[IP_STRING_LEN];
    __u32 ip_int;
    __u16 port;
}__attribute__((packed));

struct conntrack_entry {
    __u32 ip;
    __u16 port;
} __attribute__((packed));
typedef struct conntrack_entry ce;


#define RING_BUFF_MAX 1024

#define RING_BUFF_TIMEOUT 5000

struct event {
	__u64 total_bits;
    __u64 local_bits;
};