#include "slb.h"

hm backends[NUM_BACKENDS] = {
    {"172.19.0.2", 2896692482, 80},
    {"172.19.0.3", 2896692483, 80}
};
hm slb = {"172.19.0.5", 2896692485, 80};
hm vip = {"172.19.0.10", 2896692490, 80};

static __always_inline int gen_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph){
    struct bpf_fib_lookup fib_params = {};
	fib_params.family	= AF_INET;
    fib_params.tos		= iph->tos;
    fib_params.l4_protocol	= iph->protocol;
    fib_params.sport	= 0;
    fib_params.dport	= 0;
    fib_params.tot_len	= bpf_ntohs(iph->tot_len);
    fib_params.ipv4_src	= iph->saddr;
    fib_params.ipv4_dst	= iph->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int action = XDP_PASS;
    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            action = XDP_TX;
            break;
        case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
        case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
        case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
            action = XDP_DROP;
            break;
        case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
        case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
        case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
            /* PASS */
            break;
	}
    return action;
}

// todo random port within[30100,60900]
__u16 cur = 0;
static __always_inline __u16 get_port(){
    __u16 t = cur++ + NAT_PORT_MIN;
    if(t > NAT_PORT_MAX){
        return 0;
    }
    return t;
}

// todo implement different load balancing algorithm
int count = 0;
static __always_inline hm *lb_rr(){
    int backend_idx = count++ % NUM_BACKENDS;
    return &(backends[backend_idx]);
}
static __always_inline hm *lb_rand(){
    int backend_idx = bpf_get_prandom_u32() % NUM_BACKENDS;
    return &(backends[backend_idx]);  
}
static __always_inline hm *get_backend(enum LB_ALG alg){
    switch (alg){
        case round_robin:
            return lb_rr();   
        case random: 
        default:
            return lb_rand();
    }
}

SEC("xdp_slb")
int xdp_load_balancer(struct xdp_md *ctx)
{
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
        return XDP_DROP;
    }
    // __u16 new_src_port = sport;
    // __u16 new_dest_port = dport;

    if (iph->daddr == vip.ip_int){
        // Choose a backend server to send the request to; 
        hm *rs = get_backend(0);
        ce nat_key = {
            .ip = bpf_htonl(iph->saddr),
            .port = sport
        };
        ce *nat_p = bpf_map_lookup_elem(&snat_map, &nat_key);
        if (nat_p == NULL) {
            ce nat_val = {
                .ip = slb.ip_int,
                .port = get_port()
            };
            nat_p = &nat_val;
            bpf_map_update_elem(&snat_map, &nat_key, nat_p, map_flags); 
            bpf_map_update_elem(&dnat_map, nat_p, &nat_key, map_flags);       
        }
        iph->daddr = rs->ip_int;
        tcph->dest = rs->port;
        // new_dest_port = rs->port;
        iph->saddr = nat_p->ip;
        tcph->source = nat_p->port;
        // new_src_port = nat_p->port;
        bpf_printk("Got a nat packet of tuple, from %x:%x to %x:%x", iph->saddr,sport,iph->daddr,dport);
    }else{
        // send resp to client
        ce nat_key = {
            .ip = bpf_htonl(iph->daddr),
            .port = dport
        };
        ce *nat_p = bpf_map_lookup_elem(&snat_map, &nat_key);
        if (nat_p == NULL) {
            bpf_printk("No such connection from client before");
            return XDP_DROP;
        }
        iph->daddr = nat_p->ip;
        tcph->dest = nat_p->port;
        // new_dest_port = nat_p->port;
        iph->saddr = vip.ip_int;
        tcph->source = vip.port;
        // new_src_port = vip.port;
        bpf_printk("Send a nat packet of tuple, from %x:%x to %x:%x", iph->saddr,sport,iph->daddr,dport);
    }
    int action = gen_mac(ctx,eth,iph);
    iph->check = iph_csum(iph);
    tcph->check = ipv4_l4_csum(tcph, tcp_len, iph);
    return action;
}

char _license[] SEC("license") = "GPL";