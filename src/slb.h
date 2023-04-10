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

enum LB_ALG{
    lb_random, 
    lb_round_robin, 
    lb_n_hash,
};
// enum LB_ALG cur_lb_alg = lb_random;
// enum LB_ALG cur_lb_alg = lb_round_robin;
enum LB_ALG cur_lb_alg = lb_n_hash;
