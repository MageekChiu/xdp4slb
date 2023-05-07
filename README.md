随着 eBPF 的发展，我们已经可以将 eBPF/XDP 程序直接部署在普通服务器上来实现负载均衡，从而去掉用于专门部署 LVS 的机器。本系列文章就是基于这个出发点，以演进的形式，分析和探讨一些实现思路。

# 系列回顾

[版本 0.1](https://mp.weixin.qq.com/s/XjDXyNPjEzMy5jfwfO2AnA) 分享了如何使用 xdp/ebpf 替换 lvs 来实现 slb，依然采用的是 slb 独立机器部署模式，并且采用 bpftool 和硬编码配置的形式来进行加载 xdp 程序，代码在 https://github.com/MageekChiu/xdp4slb/tree/dev-0.1。

[版本 0.2](https://github.com/MageekChiu/xdp4slb/tree/dev-0.2) 在 0.1 基础上，修改为基于 [bpf skeleton](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#bpf-skeleton-and-bpf-app-lifecycle) 的程序化加载模式，要想简单地体验下这种工作流而不改动版本 0.1 中整体部署模式的，可以去看看 https://github.com/MageekChiu/xdp4slb/tree/dev-0.2。

[版本 0.3](https://github.com/MageekChiu/xdp4slb/tree/dev-0.3) 在 0.2 基础上，支持以配置文件和命令行参数的形式动态加载 slb 配置。

[版本 0.4](https://mp.weixin.qq.com/s/74OcWnQfc9dTSqOZfD-8eg) 支持 slb 和 application 混布的模式，去除了专用的 slb 机器。混布模式使得普通机器也能直接做负载均衡，同时不影响应用（off load 模式下可以体现），有成本效益；另外，在路由到本地的场景下，减少了路由跳数，整体性能更好。

[本文属于0.5](https://mp.weixin.qq.com/s/Uwd1YHL2g4WQxZxrxFA2rw)，支持使用内核能力进行 mac 寻址、健康检查、conntrack回收、向用户态透出统计数据等特性。
接下来分别进行介绍，如果你希望自己实验一下，基本的环境搭建可以[参考前文](https://mp.weixin.qq.com/s/74OcWnQfc9dTSqOZfD-8eg)。

# 特性介绍

## 使用内核进行 mac 寻址

前面的版本中，我们直接在配置文件中配置了 rs 的 mac 地址，这只是做 demo，现实中这是不太可行的，因为 ip 和 mac 的关系并不是一成不变的。因此，我们在每包路由的时候，需要动态填充 mac 地址。当然我们不需要自己去实现 arp 功能，只需要使用 bpf_fib_lookup 便可以借助内核能力查询 mac 地址，这也是不采用 kernel bypass 的好处之一，我们在提升了性能的同时，还能享受内核带来的红利。
主要代码如下，其中 ipv4_src 是本机 地址，ipv4_dst 是被选中的 rs ip：

```c
static int gen_mac(struct xdp_md *ctx, struct ethhdr *eth ,struct iphdr *iph,
                    __u32 ipv4_src, __u32 ipv4_dst){
    struct bpf_fib_lookup fib_params;
    memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family	= AF_INET;
    // ...

    int action = XDP_PASS;
    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
            memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            action = XDP_TX;
            break;
        case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
     		// ...
            action = XDP_DROP;
            break;
        case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
      		// ...
            break;
	}
    return action;
}
```

这样我们的配置文件中，就只需要填写 ip 而不需要 mac 地址了，如图：

![](/img/bVc7Hdt)

但是程序直接这样跑的话，会发现寻址结果都是 not found，因为 mix 之间并没有建立起相应的 arp 表，所以接下来的健康检查就能排上用场了。

## 健康检查
在 slb 程序中，健康检查是一个比较重要的的功能，能够及时剔除非健康节点，实现 rs 高可用。
我们这里简单起见，让每个 mix（slb 和 app 的混布产物）在启动时，在用户态访问一次其它所有 mix，这样**一方面能起到健康检查的作用，更重要的是，能够帮助内核建立 arp 表，后面我们在 xdp 中就可以直接查询，从而避免了在 xdp 自己做 arp**。

主要代码如下：

```c
static int healthz_tcp(__u32 ip, __u16 port){
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = port;
    servaddr.sin_addr.s_addr = ip;

    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		fprintf(stderr, "error socket conecting: \n");
        return 1;
    }
	
	close(sockfd);
    return 0; 
}
```

我们可以用这些命令来观察 arp 表项


```
arp -a 
arp -d mix1.south 
# or
arp -d 172.19.0.9
```

## Conntrack entry 回收

前文中，conntrack table 超过 max 后并不会导致路由发生问题（理论上），因为同一个“连接”的哈希是一致的，采用哈希负载均衡方法后，即使重新计算也会被分配到同一个后端。但是会导致反复计算“连接”的哈希值，消耗CPU。
为了避免这个问题，我们可以把 max 调大一点（不要使用 prealloc），以支持更大的并发。但是这样就可能会导致内存的浪费，因为 conntrack 的清理我们依赖的是LRU（被动清理），如果没有超过 max 就不会清理。所以，我们需要加上主动清理的步骤，来[回收内存](https://elixir.bootlin.com/linux/v6.1.11/source/kernel/bpf/hashtab.c#L1373)。

回收大致有两种方案：

1. 采用 LRU map，监听 socket 释放的事件，将事件进行 本地/组播/广播 三个级别的处理来清理对应的 conntrack entry
2. 采用 normal/ordered map + 时间戳，定期遍历并清理 stale conntrack entry

内核的做法大致是方案 2，本文采用方案 1 来试试。

首先，获得 socket 释放事件有几种做法，按照 attach type 大致可以分为
1. `SEC("tp_btf/inet_sock_set_state")`：关注 tcp 状态转变
2. `SEC("kprobe/inet_release")`：内核释放 socket 的时候会调用这个函数

由于 tracepoint 比 kprobe 更稳定，所以本文采用方案 1，代码大致为

```
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(trace_inet_sock_set_state, struct sock *sk, int oldstate,
	     int newstate){
	// 只关注 tcp 关闭状态
	if (newstate != BPF_TCP_CLOSE)
        return 0;
	
    const int type = BPF_CORE_READ(sk,sk_type);
    if(type != SOCK_STREAM){//1
        return 0;
    }
    
    const struct sock_common skc = BPF_CORE_READ(sk,__sk_common);
    const __u32 dip = (BPF_CORE_READ(&skc,skc_daddr));  
    const __u16 dport = (BPF_CORE_READ(&skc,skc_dport));
    struct inet_sock *inet = (struct inet_sock *)(sk);
    const __u32 sip = (BPF_CORE_READ(inet,inet_saddr));
    const __u16 sport = (BPF_CORE_READ(inet,inet_sport));
	// 只关注跟 vip 相关的连接
    if(sip == vip->ip_int && sport == vip->port){       
        fire_sock_release_event(dip,dport);
    }
    return 0;
}
```

在 fire_sock_release_event 中真正处理事件。这里有一个点值得特别说明，我们的实验环境在容器中，所以以上 tp 相当于在同一个内核中挂在了 n 次（n = mix 数量），所以会被重复触发，但实际上，socket 释放只会发生在**被选中的 rs** 中一次，为了避免这个缺陷，我们需要借助 `bpf_get_current_cgroup_id()` 来获取事件发生时的 cgroup，然后和本容器所在 cgroup_id 进行比较，只有匹配了，才真正触发事件。

那么容器的 cgroup_id 如何获取呢？ cgroup_id 实际上就是 cgroupfs 的 inode number， 我们只需要获得容器的 cgroupfs 然后获取 inode 即可，步骤可以是下面这样的（你可能需要依据你自己的发行版决定）：

```
# 获得容器名称和 id
docker inspect -f "{{.Name}} {{.ID}}" $(docker ps -q)

# 将 id 填进去
find /sys/fs/cgroup -name "*46282095db3a*" -o -name "*33ed500a9fd9*" | \
        xargs -n1 stat --printf='\n%n %s %y %i\n'
```

这样我们就能在 slb 启动时，将容器的 cgroup_id 作为参数传进去，然后处理事件时可用：

```
const volatile __u64 cur_cgp_id = 0;

__attribute__((always_inline)) 
static int sock_release_local(ce *nat_key){
    return bpf_map_delete_elem(&conntrack_map, nat_key); 
}

static void fire_sock_release_event(__u32 src_ip4,__u16 src_port){
    int cgrid = bpf_get_current_cgroup_id();
    if(cur_cgp_id && cur_cgp_id != cgrid){
        return;
    }
    
    ce nat_key = {
        .ip = src_ip4,
        .port = src_port
    };
    int err = sock_release_local(&nat_key);
    if(cur_clear_mode > just_local){
        ce *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        e->ip = src_ip4;
        e->port = src_port;
        bpf_ringbuf_submit(e, 0);
    }
}
```

其实就是判断本实例是否应该处理这个事件，如果应该，则先清理本地（内核空间）的，如果配置了组播/广播，则发送到用户空间去做。用户空间代码：

```
static bool forge_header(const ce *e,__u32 ip, __u16 port){
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
    addr.sin_port = port;
	int cnt = sendto(fd,e,sizeof(e),0,(struct sockaddr*) &addr,sizeof(addr));
	return true;
}

static bool do_multcast(const ce *e){
	return forge_header(e,env.gip.ip_int,env.gip.port);
}

static bool do_broadcast(const ce *e){
	// todo
	return true;
}

static int handle_event(void *ctx, void *data, size_t data_sz){
	const ce *e = data;
	bool sent = false;
	if(env.cur_clear_mode == group_cast){
		sent = do_multcast(e);
	}else if(env.cur_clear_mode == broad_cast){
		sent = do_broadcast(e);
	}
	return 0;
}

int main(int argc, char **argv){
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	while (!exiting) {
		err = ring_buffer__poll(rb, RING_BUFF_TIMEOUT);
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
}
```

其它 mix 收到后，直接在内核空间进行相应的清理，所以内核空间的整体架构如下：

```
if(iph->daddr == local_ip){
    // ... local handle 
}

int action = XDP_PASS;
if (iph->daddr == vip->ip_int){
    // ... vip handle 
}
if(gip->ip_int == iph->daddr && gip->port == dport){
    ce *payload  = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    __u32 ip = payload->ip;
    __u16 port = payload->port;
    int err = sock_release_local(payload);
    return XDP_DROP;
}
return XDP_DROP;
```

这样整个流程就完整了。代码完成后，我们可以进行压测：

```shell
# 默认清理本机
./slb -i eth0 -c ./slb.conf 
# 组播清理，若在容器中使用要配置 cgroupid，按实际情况填入；非容器环境忽略此参数
./slb -i eth0 -c ./slb.conf -g 13107 -k 3
# 不清理
./slb -i eth0 -c ./slb.conf -k 1

# client中
ab -c 500 -n 8000 http://172.19.0.10:80/
```

查看 map进行验证：

```shell
bpftool map help
bpftool map list
# 需填入实际 id
bpftool map dump id 660
bpftool map show id 660
```

## 统计数据透出

slb中，通常还会加上一些统计数据，用于监控和计费等。
这里简单的使用全局变量，统计经过本 mix 的所有包大小，以及经过 slb 到达本 app 的包的大小。注意，直接到达 app 的包不属于 slb 功能，不在统计范围内。核心代码如下：

```c
volatile __u64 total_bits = 0;

volatile __u64 local_bits = 0;

if(iph->daddr == local_ip){
    return XDP_PASS;
    // this is a direct packet to rs, so doen't count for slb statics
}
if (iph->daddr == vip->ip_int){
    if(dport != vip->port){
        return XDP_DROP;
    }
    total_bits += pkt_sz;
    // Choose a backend server to send the request to; 
    if(rs->ip_int == local_ip){
        local_bits += pkt_sz;
        return XDP_PASS;
    }
    action = gen_mac(ctx,eth,iph,local_ip,rs->ip_int);
    return action;
}
```

用户态直接这样读取即可：`skel->bss->total_bits,skel->bss->local_bits`;
因为 0 相当于未初始化，被放在了 bss 段，对 elf 不熟悉的同学，可以看看《程序员的自我修养》这本书，对链接、装载与库介绍比较完备。

# 后记

经过几个版本的迭代，这个 slb 的核心能力已经具备雏形了，接下来可以继续完善的有
- 完善的边界检查，避免错误配置
- conntrack 清理这里被建模成一个分布式一致性问题，只是对一致性要求不高，如果你希望更完善，完全可以结合常见的分布式一致性协议来实现（如果做了集群间同步，就可以支持更多的负载均衡算法）；或者另起炉灶，比如按照内核或者 cilium 的思路来实现
- 支持 udp 协议
- 支持 full nat
- ...

# 参考
- https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_core.c
- https://elixir.bootlin.com/linux/v6.1.11/source/kernel/bpf/hashtab.c#L459
- https://elixir.bootlin.com/linux/v6.1.11/source/kernel/bpf/hashtab.c#L1373
- https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps_types.html#implementation-details
- https://patchwork.ozlabs.org/project/netdev/patch/20180603225943.2370719-2-yhs@fb.com/
- https://github.com/iovisor/bpftrace/issues/1500

