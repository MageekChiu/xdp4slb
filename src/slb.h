#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif


#define ETH_P_IP	0x0800		
#define ETH_ALEN 6
// #undef AF_INET
// #define AF_INET 2
#define TCP_MAX_BITS 1480


#define MAX_U_32_INT 4294967295.0
#define NAT_PORT_MIN 30100
#define NAT_PORT_MAX 60900
#define NAT_PORT_RANGE (NAT_PORT_MAX - NAT_PORT_MIN)


#define ARP_MAP_SIZE 4096
#define SNAT_MAP_SIZE 4096
#define DNAT_MAP_SIZE 4096
#define BACKEND_MAP_SIZE 4096

#define MAX_BACKEND 8

enum LB_ALG{
    lb_random = 1, 
    lb_round_robin = 2, 
    lb_n_hash = 3,
};

typedef unsigned int __u32;
typedef short unsigned int __u16;
typedef unsigned char __u8;

struct host_meta {
    char *ip;
    __u32 ip_int;
    __u8 mac_addr[ETH_ALEN];
    __u16 port;
}__attribute__((packed));
