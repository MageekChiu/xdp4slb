#include "slb.h"
#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


// convenient for debugging
// #define NUM_BACKENDS 1
#define NUM_BACKENDS 2
struct host_meta {
    char *ip;
    __u32 ip_int;
    unsigned char mac_addr[ETH_ALEN];
    __u16 port;
};

struct conntrack_entry {
    __u32 ip;
    __u16 port;
} __attribute__((packed));
typedef struct conntrack_entry ce;

__attribute__((always_inline))
static  __u16 csum_fold_helper(__u64 csum){
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

__attribute__((always_inline))
static __u16 iph_csum(struct iphdr *iph){
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

__attribute__((always_inline))
static  __u16 ipv4_l4_csum(void* data_start, __u32 data_size, struct iphdr* iph,void *data_end) {
    __u64 csum_buffer = 0;
    __u16 *buf = (void *)data_start;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u32)iph->protocol << 8;
    csum_buffer += data_size;

    // Compute checksum on udp/tcp header + payload
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


__u32 map_flags = BPF_ANY;

// enum LB_ALG cur_lb_alg = lb_random;
// enum LB_ALG cur_lb_alg = lb_round_robin;
enum LB_ALG cur_lb_alg = lb_n_hash;

static struct host_meta backends[NUM_BACKENDS] = {
    {"172.19.0.2", bpf_htonl(2886926338), {0x02, 0x42, 0xac, 0x13, 0x00, 0x02}, bpf_htons(80)},
    {"172.19.0.3", bpf_htonl(2886926339), {0x02, 0x42, 0xac, 0x13, 0x00, 0x03}, bpf_htons(80)}
};
static struct host_meta slb = {"172.19.0.5", bpf_htonl(2886926341), {0x02, 0x42, 0xac, 0x13, 0x00, 0x05}, bpf_htons(80)};
// On fedora 37:"ifconfig eth0:0 172.19.0.10/32 hw ether 02:42:ac:13:00:10 up" would change mac addr of eth0, 
// cause interface aliases are not created using "eth0:0"(deprecated in modern linux distributions)
// so we have to reuse mac addr and use "ifconfig eth0:0 172.19.0.10/32 up"
// However,reusing mac addr would also cause problem(arp and so on)
// In fact all these distors above would change mac addr of eth0 with "ifconfig xxx mac addr" the problem is not about this
// It is again the way of loading
// https://github.com/libbpf/libbpf-rs/issues/185 
static struct host_meta vip = {"172.19.0.10", bpf_htonl(2886926346), {0x02, 0x42, 0xac, 0x13, 0x00, 0x10}, bpf_htons(80)};


// client ip:port -> slb ip:port
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SNAT_MAP_SIZE);
    __type(key, ce);
    __type(value, ce);
} snat_map SEC(".maps");

// slb ip:port -> client ip:port
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DNAT_MAP_SIZE);
    __type(key, ce);
    __type(value, ce);
} dnat_map SEC(".maps");

// client ip -> the corresponding mac
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, ARP_MAP_SIZE);
    __type(key, __u32);
    __type(value, unsigned char [ETH_ALEN]);
} arp_map SEC(".maps");

// client ip:port -> the corresponding backend
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, BACKEND_MAP_SIZE);
    __type(key, ce);
    __type(value, struct host_meta);
} back_map SEC(".maps");


__attribute__((always_inline))
static void print_mac(char *prefix ,unsigned char mac[ETH_ALEN]){
    bpf_printk("%s %02x:%02x:%02x:%02x:%02x:%02x",
        prefix,mac[0],mac[1],mac[2],
        mac[3],mac[4],mac[5]
    );
}
__attribute__((always_inline))
static int gen_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph,
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

__attribute__((always_inline))
static void l4_ingress(struct iphdr *iph, struct tcphdr *tcph, ce *src, struct host_meta *dst){
    // net edian allready
    iph->saddr = (src->ip);
    tcph->source = (src->port);
    iph->daddr = (dst->ip_int);
    tcph->dest = (dst->port);
}

__attribute__((always_inline))
static void l4_egress(struct iphdr *iph, struct tcphdr *tcph, struct host_meta *src, ce *dst){
    // net edian allready
    iph->saddr = (src->ip_int);
    tcph->source = (src->port);
    iph->daddr = (dst->ip);
    tcph->dest = (dst->port);
}


// todo random port within[30100,60900]
__attribute__((always_inline))
static __u16 get_src_port(){
    // bpf_printk("NAT PORT");

    static __u16 cur = 0;
    __u16 t = (__u16)(cur++ + NAT_PORT_MIN);
    if(t == NAT_PORT_MAX){
        cur = 0;
    }
    __u16 r = bpf_htons(t);
    // bpf_printk("NAT r:%u ",r);
    // bpf_printk("NAT cur:%u ,t:%u ",cur,t);
    bpf_printk("NAT PORT cur:%u ,t:%u ,r:%u",cur,t,r);
    return r;
    
    // __u32 port = bpf_get_prandom_u32();
    // __u32 p = (port % NAT_PORT_RANGE) + NAT_PORT_MIN;
    // __u16 r = bpf_ntohs((__u16)p);
    // bpf_printk("NAT PORT cur:%u ,p:%u ,r:%u",port,p,r);
    // return r;
}

__attribute__((always_inline))
static __u32 get_src_ip(){
    bpf_printk("NAT IP %u",slb.ip_int);
    return slb.ip_int;
}


// todo implement different load balancing algorithm
__attribute__((always_inline))
static struct host_meta *lb_hash(ce *nat_key){
    // with hash, we dobn't need to sync session amongst slb intances
    __u32 hash = ((nat_key->ip >> 7) & nat_key->port >> 3);
    bpf_printk("LB hash %u",hash);
    __u32 backend_idx = hash % NUM_BACKENDS;
    return &(backends[backend_idx]);
}

__attribute__((always_inline))
static struct host_meta *lb_rr(){
    static __u32 count = 0;
    __u32 backend_idx = count++ % NUM_BACKENDS;
    return &(backends[backend_idx]);
}

__attribute__((always_inline)) 
static struct host_meta *lb_rand(){
    __u32 backend_idx = bpf_get_prandom_u32() % NUM_BACKENDS;
    return &(backends[backend_idx]);  
}

__attribute__((always_inline)) 
static struct host_meta *get_backend(enum LB_ALG alg,ce *nat_key){
    switch (alg){
        case lb_round_robin:
            return lb_rr();   
        case lb_n_hash:
            return lb_hash(nat_key);
        case lb_random: 
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
    // __u32 sip = (iph->saddr);
    // __u32 dip = (iph->daddr);
    // __u16 sport = bpf_ntohs(tcph->source);
    // __u16 dport = bpf_ntohs(tcph->dest);
    __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);
    // https://www.kernel.org/doc/html/latest/core-api/printk-formats.html#ipv4-addresses
    // bpf_printk("Got a TCP packet of tuple, from %pI4:%u to %pI4:%u, lenL:%u", iph->saddr,sport,iph->daddr,dport,tcp_len);
    bpf_printk("Got a TCP packet of tuple \n \
            from %u|%pI4:%u|%u to %u|%pI4:%u|%u, \n \
            iph->daddr: %u|%pI4, vip.ip_int: %u|%pI4 ",
    iph->saddr,&(iph->saddr),tcph->source,bpf_ntohs(tcph->source),
    iph->daddr,&(iph->daddr),tcph->dest, bpf_ntohs(tcph->dest),
    iph->daddr,&(iph->daddr),vip.ip_int,&(vip.ip_int));
    if (tcp_len > TCP_MAX_BITS){
        bpf_printk("Tcp_len %u larger than max , drop",tcp_len);
        return XDP_DROP;
    }
    // bpf_printk("dip \n%u %u %u \n%u,%u %u",
    //     // bpf_ntohl bpf_htonl all just flip, the func name is bad
    //     dip,bpf_ntohl(dip),bpf_htonl(dip),
    //     vip.ip_int,bpf_ntohl(vip.ip_int),bpf_htonl(vip.ip_int)
    // );

    int action = XDP_PASS;
    if (iph->daddr == vip.ip_int){
        if(tcph->dest != vip.port){
            bpf_printk("No such port %u , drop",bpf_ntohs(tcph->dest));
            return XDP_DROP;
        }
        // Choose a backend server to send the request to; 
        // within a lifetime of tcp conn, backend must be the same
        ce nat_key = {
            // keep the original net edian
            .ip = iph->saddr,
            .port = tcph->source
        };
        struct host_meta *rs = bpf_map_lookup_elem(&back_map, &nat_key);
        if (rs == NULL){
            rs = get_backend(cur_lb_alg,&nat_key);
            bpf_map_update_elem(&back_map, &nat_key, rs, map_flags); 
        }
        ce *nat_p = bpf_map_lookup_elem(&snat_map, &nat_key);
        if (nat_p == NULL) {
            __u32 n_ip = get_src_ip();
            __u16 n_port = get_src_port();
            ce nat_val = {
                .ip = n_ip,
                .port = n_port,
            };
            nat_p = &nat_val;
            // client src -> slb src
            bpf_map_update_elem(&snat_map, &nat_key, nat_p, map_flags); 
            //  slb src  -> client src
            bpf_map_update_elem(&dnat_map, nat_p, &nat_key, map_flags);

            // arp table       
            bpf_map_update_elem(&arp_map, &(iph->saddr), eth->h_source, map_flags);       
        }
        l4_ingress(iph,tcph,nat_p,rs);
        action = gen_mac(ctx,eth,iph,slb.mac_addr,rs->mac_addr);
        bpf_printk("Ingress a nat packet of tuple\n \
        from %u|%pI4n:%u|%u to %u|%pI4n:%u|%u,", 
        iph->saddr,&(iph->saddr),tcph->source,bpf_ntohs(tcph->source),
        iph->daddr,&(iph->daddr),tcph->dest,bpf_ntohs(tcph->dest));
    }else{
        // disable this branch, so the error out put is clearer
        // return XDP_PASS;
        ce nat_key = {
            .ip = iph->daddr,
            .port = tcph->dest
        };
        ce *nat_p = bpf_map_lookup_elem(&dnat_map, &nat_key);
        if (nat_p == NULL) {
            bpf_printk("No such connection from client before,IP");
            return XDP_PASS;
        }
        l4_egress(iph,tcph,&vip,nat_p);
        unsigned char *mac_addr = bpf_map_lookup_elem(&arp_map, &iph->daddr);
        if (!mac_addr) {
            bpf_printk("No such connection from client before,MAC");
            return XDP_PASS;
        }
        action = gen_mac(ctx,eth,iph,vip.mac_addr,mac_addr);
        bpf_printk("Egress a nat packet of tuple\n \
        from %u|%pI4n:%u|%u to %u|%pI4n:%u|%u,", 
        iph->saddr,&(iph->saddr),tcph->source,bpf_ntohs(tcph->source),
        iph->daddr,&(iph->daddr),tcph->dest,bpf_ntohs(tcph->dest));
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