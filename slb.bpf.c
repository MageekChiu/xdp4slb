#include "slb.h"

hm backends[NUM_BACKENDS] = {
    {"172.19.0.2", 2896692482, {0x02, 0x42, 0xac, 0x13, 0x00, 0x02}, 80},
    {"172.19.0.3", 2896692483, {0x02, 0x42, 0xac, 0x13, 0x00, 0x03}, 80}
};
hm slb = {"172.19.0.5", 2896692485, {0x02, 0x42, 0xac, 0x13, 0x00, 0x05}, 80};
hm vip = {"172.19.0.10", 2896692490, {0x02, 0x42, 0xac, 0x13, 0x00, 0x10}, 80};

unsigned char client_mac[ETH_ALEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

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

static __attribute__((always_inline)) int gen_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph,
                unsigned char new_src[ETH_ALEN],unsigned char new_dest[ETH_ALEN]){  
    memcpy(eth->h_source, new_src, ETH_ALEN);
    memcpy(eth->h_dest, new_dest, ETH_ALEN);
    return XDP_TX;
}
// static __attribute__((always_inline)) int gen_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph){
//     struct bpf_fib_lookup fib_params = {};
// 	fib_params.family	= AF_INET;
//     fib_params.tos		= iph->tos;
//     fib_params.l4_protocol	= iph->protocol;
//     fib_params.sport	= 0;
//     fib_params.dport	= 0;
//     fib_params.tot_len	= bpf_ntohs(iph->tot_len);
//     fib_params.ipv4_src	= iph->saddr;
//     fib_params.ipv4_dst	= iph->daddr;
//     fib_params.ifindex = ctx->ingress_ifindex;

//     int action = XDP_PASS;
//     int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
//     switch (rc) {
//         case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
//             memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
//             memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
//             action = XDP_TX;
//             break;
//         case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
//         case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
//         case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
//             action = XDP_DROP;
//             break;
//         case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
//         case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
//         case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
//         case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
//         case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
//             /* PASS */
//             break;
// 	}
//     return action;
// }


// todo random port within[30100,60900]
__u16 cur = 0;
static __attribute__((always_inline)) __u16 get_src_port(){
    __u16 t = cur++ + NAT_PORT_MIN;
    if(t > NAT_PORT_MAX){
        cur = 0;
        return 0;
    }
    return t;
}
static __attribute__((always_inline)) __u32 get_src_ip(){
    return slb.ip_int;
}


// todo implement different load balancing algorithm
int count = 0;
static __attribute__((always_inline)) hm *lb_rr(){
    int backend_idx = count++ % NUM_BACKENDS;
    return &(backends[backend_idx]);
}

static __attribute__((always_inline)) hm *lb_rand(){
    int backend_idx = bpf_get_prandom_u32() % NUM_BACKENDS;
    return &(backends[backend_idx]);  
}

static __attribute__((always_inline)) hm *get_backend(enum LB_ALG alg){
    switch (alg){
        case round_robin:
            return lb_rr();   
        case random: 
        default:
            return lb_rand();
    }
}


SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
    // test where error is
    // return XDP_PASS;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    bpf_printk("Got a packet");
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    __u16 sport = bpf_ntohs(tcph->source);
    __u16 dport = bpf_ntohs(tcph->dest);
    __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
    bpf_printk("Got a TCP packet of tuple, from %x:%x to %x:%x, len", iph->saddr,sport,iph->daddr,dport,tcp_len);
    if (tcp_len > TCP_MAX_BITS){
        return XDP_PASS;
    }

    int action = XDP_PASS;
    if (iph->daddr == vip.ip_int){
        // Choose a backend server to send the request to; 
        hm *rs = get_backend(random);
        ce nat_key = {
            .ip = bpf_htonl(iph->saddr),
            .port = sport
        };
        ce *nat_p = bpf_map_lookup_elem(&snat_map, &nat_key);
        if (nat_p == NULL) {
            ce nat_val = {
                .ip = get_src_ip(),
                .port = get_src_port()
            };
            nat_p = &nat_val;
            bpf_map_update_elem(&snat_map, &nat_key, nat_p, map_flags); 
            bpf_map_update_elem(&dnat_map, nat_p, &nat_key, map_flags);       
        }
        iph->daddr = rs->ip_int;
        tcph->dest = rs->port;
        iph->saddr = nat_p->ip;
        tcph->source = nat_p->port;
        action = gen_mac(ctx,eth,iph,slb.mac_addr,rs->mac_addr);
        bpf_printk("Got a nat packet of tuple, from %x:%x to %x:%x", iph->saddr,sport,iph->daddr,dport);
    }else{
        // disable this branch, so the error out put is clearer
        return XDP_PASS;
        ce nat_key = {
            .ip = bpf_htonl(iph->daddr),
            .port = dport
        };
        ce *nat_p = bpf_map_lookup_elem(&snat_map, &nat_key);
        if (nat_p == NULL) {
            bpf_printk("No such connection from client before");
            return XDP_PASS;
        }
        iph->daddr = nat_p->ip;
        tcph->dest = nat_p->port;
        iph->saddr = vip.ip_int;
        tcph->source = vip.port;
        action = gen_mac(ctx,eth,iph,vip.mac_addr,client_mac);
        bpf_printk("Send a nat packet of tuple, from %x:%x to %x:%x", iph->saddr,sport,iph->daddr,dport);
    }
    // action = gen_mac(ctx,eth,iph);
    iph->check = iph_csum(iph);
    // here is the problem
    // return XDP_PASS;
    tcph->check = ipv4_l4_csum(tcph, tcp_len, iph,data_end);
    // return action;
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";