[前文](https://segmentfault.com/a/1190000041048935)分析了 LVS 作为负载均衡的原理。随着 eBPF 的发展，我们已经可以[将 eBPF/XDP 程序直接部署在普通服务器上来实现负载均衡](https://github.com/facebookincubator/katran)，从而节省掉用于专门部署 LVS 的机器。

本文不打算直接到这一步，而是首先看看如何用 eBPF/XDP 按照常规模式来替代 LVS，也就是说我们还是将负载均衡程序（software load balance 简称 SLB）部署在专用机器上，只不过不用 LVS，而是用 eBPF/XDP 来实现。

# 实验步骤

## 创建网络环境

```shell
# 不同发行版命令不一样
systemctl start docker

docker network create south --subnet 172.19.0.0/16 --gateway 172.19.0.1

# check
docker network inspect south
# or
ip link

# 先用 ifconfig 获得刚创建的 network 应的 bridge
# 后续则可以在宿主机上抓取这个 network 的所有 IP 包
tcpdump -i br-3512959a6150 ip
# 也可以获得某个容器的 veth ,抓取这个容器进出的所有包
tcpdump -i vethf01d241  ip
# 当然，如果是 offload 的模式，则调试确实不易，需要嗅探本地网络的数据包并抓取了
# 在容器网络里，我们尚有宿主机这个上帝视角，在裸机网络里，则可能得去捯饬路由器了

```
![image.png](https://segmentfault.com/img/bVc7dCi)

## 创建两个RS

```shell
echo "rs-1" > rs1.html
echo "rs-2" > rs2.html

docker run -itd --name rs1 --hostname rs1 --privileged=true --net south -p 8888:80 --ip 172.19.0.2 --mac-address="02:42:ac:13:00:02" -v "$(pwd)"/rs1.html:/usr/share/nginx/html/index.html:ro nginx:stable

docker run -itd --name rs2 --hostname rs2 --privileged=true --net south -p 9999:80 --ip 172.19.0.3 --mac-address="02:42:ac:13:00:03" -v "$(pwd)"/rs2.html:/usr/share/nginx/html/index.html:ro nginx:stable

# check on host
curl 127.0.0.1:8888
curl 127.0.0.1:9999

```

另：
即使是 nginx 对于我们调试负载均衡也不是足够简单，调试阶段可以用 nc 来进行调试
`dnf install nc or apt install netcat`
server side `nc -l -vv -p 5000`
client side `nc 172.19.0.2 5000`

## 实现SLB

为了不影响 RS，本文采用 [NAT](http://www.linuxvirtualserver.org/VS-NAT.html) 模式的进一步：[Full-NAT](https://blog.csdn.net/weixin_51867896/article/details/123646168) 模式实现 SLB。这种模式有缺陷：rs 不能获得真实的 client ip，但是对部署环境要求相对较少（网络相通，无需设置默认网关）。

### 实现分析

源码都在 [https://github.com/MageekChiu/xdp4slb](https://github.com/MageekChiu/xdp4slb)。欢迎大家提出缺陷和建议！

核心框架如下:

```
if (dest_ip = vip && dest_port = vport){
	ingress，包来源于 client，要转发给 rs	
	挑选本地一个可用的 port1-ip1 作为新包的 src
	使用负载均衡算法挑选一个 rs，并将其 port2-ip2 作为新包的 dst
	相应的修改 src mac 和 dst mac
	
	此外保存 client 的 port3-ip3 和 port1-ip1 的双向映射关系
	便于后续 ingress 和 egress 使用
}else{
	egress，包来源于 rs， 要转发给 client
	根据包的 dst 找到 port1-ip1
	根据 ingress 里面的映射找到对应的 client 的 port3-ip3 作为新包的 dst
	使用 vip 和 vport 作为新包的 src
	相应的修改 src mac 和 dst mac 
}
重新计算校验和
使用 XDP_TX 将包从本网卡重新扔回去
```
这里面还有些校验细节就不讲了，大家可以直接看代码

### 本地测试

开发完成后，可以先在本地进行编译和load，以提前暴露问题，没问题后，在将目标文件放到容器里进行测试

```
# CORE, if you want to include vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# local compile and test
rm -f /sys/fs/bpf/slb \
	&& rm -f slb.bpf.o \
	&& clang -target bpf -g -O2 -c slb.bpf.c -o slb.bpf.o \
	&& bpftool prog load slb.bpf.o /sys/fs/bpf/slb \
	&& ll /sys/fs/bpf/slb \
	# for testing, you can cp newly compiled object to container
	docker cp slb.bpf.o slb:/tmp/
```


## 部署和配置SLB

Dockerfile 如下

```
FROM debian:bullseye
# modify source to get faster installation
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list \
    && apt-get update -y && apt-get upgrade -y \
    && apt install -y procps bpftool iproute2 net-tools telnet kmod curl tcpdump

WORKDIR /tmp/
COPY slb.bpf.o /tmp/

```

构建镜像并运行

```
docker build -t mageek/slb:0.1 .

docker run -itd --name slb --hostname slb --privileged=true --net south --ip 172.19.0.5 --mac-address="02:42:ac:13:00:05" mageek/slb:0.1
```

进入容器加载 xdp 目标文件

```
docker exec -it slb bash

# 在SLB中启用VIP
# reuse mac addr from slb ip
# ifconfig eth0:0 172.19.0.10/32 up
# add new mac for vip
ifconfig eth0:0 172.19.0.10/32 hw ether 02:42:ac:13:00:10 up
# to delete
# ifconfig eth0:0 down

bpftool net detach xdpgeneric dev eth0
rm /sys/fs/bpf/slb

bpftool prog load slb.bpf.o /sys/fs/bpf/slb
# ls -l  /sys/fs/bpf
bpftool prog list
# bpftool prog show name xdp_lb  --pretty

# bpftool net attach xdpgeneric name xdp_lb  dev eth0
# or
bpftool net attach xdpgeneric id 211 dev eth0
# check with 
ip link

cat /sys/kernel/debug/tracing/trace_pipe
# better use code bellow
bpftool prog tracelog

# won't get any result, cause the packets haven't got there
tcpdump host 172.19.0.10
```

注意，虽然官方文档上说，attach xdp 会自己选择合适的模式，但是我们在虚拟网卡下面，只能选择 attach xdpgeneric，前者不会生效，估计是个bug。


## 测试

新起一个client容器

```
docker run -itd --name client --hostname client --privileged=true --net south -p 10000:80 --ip 172.19.0.9 --mac-address="02:42:ac:13:00:09" nginx:stable
```

进入 client

```
docker exec -it client bash

# visit rs first
curl 172.19.0.2:80
curl 172.19.0.3:80

# visit slb 
curl 172.19.0.10:80
rs-1
curl 172.19.0.10:80
rs-2
curl 172.19.0.10:80
rs-1
curl 172.19.0.10:80
rs-2

```

可见确实实现了 round_robin 算法。

# 限制

TCP的负载均衡是比较复杂的，还有各种条件需要考虑，比如：多实例 SLB 之间的状态同步、conntrack 条目的回收、端口自动管理、arp动态处理等等。完整的实现是非常复杂和体系化的，本文作为一个简单的实现，目的是体验ebpf/xdp，生产级别的实现请自行完成（工作量较大）或参考社区已有版本（虽然不多）。

# 参考

- https://github.com/torvalds/linux/blob/master/net/netfilter/nf_nat_core.c#L504
- https://github.com/lizrice/lb-from-scratch/blob/main/README.MD
- https://github.com/xdp-project/xdp-tutorial
- https://blog.csdn.net/hbhgyu/article/details/109600180
- https://lists.iovisor.org/g/iovisor-dev/topic/30315706
- https://github.com/iovisor/bcc/issues/2463
- https://github.com/facebookincubator/katran/blob/master/katran/lib/bpf/balancer_helpers.h
- https://man.archlinux.org/man/bpftool-net.8.en
- https://stackoverflow.com/questions/75849176/why-my-xdp-program-with-xdp-tx-not-working
- https://www.kernel.org/doc/html/latest/core-api/printk-formats.html#ipv4-addresses

# 下文预告

本文采用了 [bpftool](https://github.com/libbpf/bpftool) 来手动加载 eBPF 程序，并且 VIP 和 RIP 都是 hard code。后面可以使用 [libbpf](https://github.com/libbpf/libbpf) 来支持 eBPF 的程序化加载和 VIP 配置。 

另，本文体验了 xdp 如何替换 LVS 实现负载均衡功能，但是并没有充分体现 xdp 的优势，下回将分析 xdp 的真正优势场景：直接部署在普通服务器上，去掉专用的 LVS 服务器。
