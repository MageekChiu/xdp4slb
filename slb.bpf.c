#include "slb.h"

hm backends[NUM_BACKENDS] = {
    {"172.19.0.2", 2896692482, 80},
    {"172.19.0.3", 2896692483, 80}
};
hm slb = {"172.19.0.5", 2896692485, 80};
hm vip = {"172.19.0.10", 2896692490, 80};

static __always_inline int parse_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph){
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
            action = bpf_redirect(fib_params.ifindex, 0);
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

SEC("xdp_slb")
int xdp_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    bpf_printk("got a packet");

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_ABORTED;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    bpf_printk("Got TCP packet from %x", iph->saddr);

    if (iph->daddr == vip.ip_int){
        // Choose a backend server to send the request to
        int backend_idx = bpf_get_prandom_u32() % NUM_BACKENDS;
        hm rs = backends[backend_idx];
        iph->daddr = rs.ip_int;
        iph->saddr = slb.ip_int;
        // *(eth->h_dest) = "ss";
        // *(eth->h_source) = "ss";
    }else{
        // send resp to client
        __u32 client_ip = 1;
        iph->daddr = client_ip;
        iph->saddr = vip.ip_int;
        // *(eth->h_dest) = "ss";
        // *(eth->h_source) = "ss";
    }
    // bpf_fib_lookup();
    int action = parse_mac(ctx,eth,iph);
    iph->check = iph_csum(iph);
    return action;
}

char _license[] SEC("license") = "GPL";