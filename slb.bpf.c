#include "slb.h"

hm backends[NUM_BACKENDS] = {
    {"172.19.0.2", bpf_htonl(2886926338), {0x02, 0x42, 0xac, 0x13, 0x00, 0x02}, 80},
    // {"172.19.0.3", bpf_htonl(2886926339), {0x02, 0x42, 0xac, 0x13, 0x00, 0x03}, 80}
};
hm slb = {"172.19.0.5", bpf_htonl(2886926341), {0x02, 0x42, 0xac, 0x13, 0x00, 0x05}, 80};
hm vip = {"172.19.0.10", bpf_htonl(2886926346), {0x02, 0x42, 0xac, 0x13, 0x00, 0x10}, 80};

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
                unsigned char n_s[ETH_ALEN],unsigned char n_d[ETH_ALEN]){  
   

    // https://nakryiko.com/posts/bpf-tips-printk/ not supported yet
    // bpf_printk("origin: 0x%pM   to 0x%pM  \n \
    // now 0x%pM   to 0x%pM   ",
    // eth->h_source,eth->h_dest,
    // n_s,n_d);

    // not enough param number in one line
    bpf_printk("origin- %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_source[0],eth->h_source[1],eth->h_source[2],
        eth->h_source[3],eth->h_source[4],eth->h_source[5]
    );
    bpf_printk("to----- %02x:%02x:%02x:%02x:%02x:%02x",
        eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],
        eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]
    );
    bpf_printk("now---- %02x:%02x:%02x:%02x:%02x:%02x",
        n_s[0],n_s[1],n_s[2],n_s[3],n_s[4],n_s[5]
    );
    bpf_printk("to----- %02x:%02x:%02x:%02x:%02x:%02x",
        n_d[0],n_d[1],n_d[2],n_d[3],n_d[4],n_d[5]
    );

    // unable to load
    // char msg[256];
    // int len = 0;
    // len += sprintf(msg +len,"origin %pM to ", eth->h_source);
    // len += sprintf(msg +len,"%pM,\n" ,eth->h_dest);
    // len += sprintf(msg +len,"now %pM to", n_s);
    // len += sprintf(msg +len,"%pM", n_d);
    // bpf_printk("gen_mac %s ",msg);

    // too many arguments to function call, expected 5, have 7
    // char msg[128];
    // bpf_snprintf(msg,sizeof(msg),"origin %pM to %pM, now %pM to %pM",eth->h_source,eth->h_dest,n_s,n_d);
    // bpf_printk("gen_mac %s ",msg);

    // unable to load
    // char msg[128];
    // int len = 0;
    // len += bpf_snprintf(msg + len,sizeof(msg) - len,"origin %pM to ", eth->h_source,sizeof(eth->h_source));
    // len += bpf_snprintf(msg + len,sizeof(msg) - len,"%pM,\n" ,eth->h_dest,sizeof(eth->h_dest));
    // len += bpf_snprintf(msg + len,sizeof(msg) - len,"now %pM to", n_s,sizeof(n_s));
    // len += bpf_snprintf(msg + len,sizeof(msg) - len,"%pM", n_d,sizeof(n_d));
    // bpf_printk("gen_mac %s ",msg);

    memcpy(eth->h_source, n_s, ETH_ALEN);
    memcpy(eth->h_dest, n_d, ETH_ALEN);
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
    if(t == NAT_PORT_MAX){
        cur = 0;
    }
    return bpf_htons(t);
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
int xdp_lb(struct xdp_md *ctx)
{
    // test where error is
    // return XDP_PASS;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    bpf_printk("Got a packet");
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)){
        bpf_printk("Not IPV4, pass");
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    // u8,so no big or little edian
    if (iph->protocol != IPPROTO_TCP){
        bpf_printk("Not TCP, pass");
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    // the definition in ip.h is __be32 in tcp.h is 
    __u32 sip = (iph->saddr);
    __u32 dip = (iph->daddr);
    __u16 sport = bpf_ntohs(tcph->source);
    __u16 dport = bpf_ntohs(tcph->dest);
    __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
    // https://www.kernel.org/doc/html/latest/core-api/printk-formats.html#ipv4-addresses
    // bpf_printk("Got a TCP packet of tuple, from %pI4:%u to %pI4:%u, lenL:%u", iph->saddr,sport,iph->daddr,dport,tcp_len);
    bpf_printk("Got a TCP packet of tuple \n \
            from %u|%pI4:%u|%u to %u|%pI4:%u|%u, \n \
            iph->daddr: %u|%pI4, vip.ip_int: %u|%pI4 ",
    sip,&sip,tcph->source,sport,dip,&dip,tcph->dest,dport,
    iph->daddr,&(iph->daddr),(vip.ip_int),&((vip.ip_int)));
    if (tcp_len > TCP_MAX_BITS){
        bpf_printk("tcp_len %u larger than max , drop");
        return XDP_DROP;
    }
    // bpf_printk("dip \n%u %u %u \n%u,%u %u",
    //     // bpf_ntohl bpf_htonl all just flip, the func name is bad
    //     dip,bpf_ntohl(dip),bpf_htonl(dip),
    //     vip.ip_int,bpf_ntohl(vip.ip_int),bpf_htonl(vip.ip_int)
    // );

    int action = XDP_PASS;
    if (dip == vip.ip_int){
        if(dport != vip.port){
            return XDP_DROP;
        }
        // Choose a backend server to send the request to; 
        hm *rs = get_backend(random);
        ce nat_key = {
            // keep the original net edian
            .ip = iph->saddr,
            .port = tcph->source
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
        // net edian allready
        iph->saddr = (nat_p->ip);
        tcph->source = (nat_p->port);
        iph->daddr = (rs->ip_int);
        tcph->dest = (rs->port);
        action = gen_mac(ctx,eth,iph,slb.mac_addr,rs->mac_addr);
        bpf_printk("Forward a nat packet of tuple\n \
        from %u|%pI4n:%u|%u to %u|%pI4n:%u|%u,", 
        iph->saddr,&iph->saddr,bpf_ntohs(nat_p->port),tcph->source,
        iph->daddr,&iph->daddr,bpf_ntohs(rs->port),tcph->dest);
    }else{
        // disable this branch, so the error out put is clearer
        // return XDP_PASS;
        ce nat_key = {
            .ip = dip,
            .port = dport
        };
        ce *nat_p = bpf_map_lookup_elem(&dnat_map, &nat_key);
        if (nat_p == NULL) {
            bpf_printk("No such connection from client before");
            return XDP_PASS;
        }
        iph->saddr = bpf_htonl(vip.ip_int);
        tcph->source = bpf_htons(vip.port);
        iph->daddr = bpf_htonl(nat_p->ip);
        tcph->dest = bpf_htons(nat_p->port);
        action = gen_mac(ctx,eth,iph,vip.mac_addr,client_mac);
        bpf_printk("Send a nat packet of tuple\n \
        from %u|%pI4n:%u|%u to %u|%pI4n:%u|%u,", 
        iph->saddr,&iph->saddr,vip.port,tcph->source,
        iph->daddr,&iph->daddr,nat_p->port,tcph->dest);
    }
    // action = gen_mac(ctx,eth,iph);
    __sum16	ip_sum = iph->check;
    iph->check = iph_csum(iph);
    __sum16	tcp_sum = tcph->check;
    // here is the problem
    // return XDP_PASS;
    tcph->check = ipv4_l4_csum(tcph, tcp_len, iph,data_end);
    // return action;
    bpf_printk("ip_sum from %u to %u,tcp_sum from %u to %u,action:%u",
       ip_sum,iph->check,tcp_sum,tcph->check,action);
    return action;
}

char _license[] SEC("license") = "GPL";