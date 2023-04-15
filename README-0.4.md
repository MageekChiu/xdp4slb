随着 eBPF 的发展，我们已经可以将 eBPF/XDP 程序直接部署在普通服务器上来实现负载均衡，从而节省掉用于专门部署 LVS 的机器。

[前文](https://mp.weixin.qq.com/s/XjDXyNPjEzMy5jfwfO2AnA) 分享了如何使用 xdp/ebpf 替换 lvs 来实现 slb，采用的是 slb 独立机器部署模式，并且采用 bpftool 和硬编码配置的形式来进行加载 xdp 程序，这是 [版本 0.1](https://github.com/MageekChiu/xdp4slb/tree/dev-0.1)。

[版本 0.2](https://github.com/MageekChiu/xdp4slb/tree/dev-0.2) 在 0.1 基础上，修改为基于 [bpf skeleton](https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#bpf-skeleton-and-bpf-app-lifecycle) 的程序化加载模式，要想简单地体验下这种工作流而不改动 版本0.1 中整体部署模式的，可以去看看 https://github.com/MageekChiu/xdp4slb/tree/dev-0.2。

[版本 0.3](https://github.com/MageekChiu/xdp4slb/tree/dev-0.3) 在 0.2 基础上，支持以配置文件和命令行参数的形式动态加载 slb 配置

本文属于 [版本 0.4](https://github.com/MageekChiu/xdp4slb/blob/dev-0.4/README-0.4.md)，支持 slb 和 application 混布的模式，去除了专用的 slb 机器。
混布模式使得普通机器也能直接做负载均衡，同时不影响应用（off load 模式下可以体现），有成本效益；另外，在路由到本地的场景下，减少了路由跳数，整体性能更好。

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

```

# 原理解析

## SLB 集群路由

slb 为了高可用，一般都会集群化部署，那么请求怎么路由到每一台 slb 上呢？一般由（动态）路由协议（ospf bgp）实现 ecmp，使得各个 slb 实例从 router/switch 那里均匀地获得流量。
由于配置动态路由协议非常繁杂，不在本文考虑范围之内，这里采用一个简单的脚本来模拟 ecmp。

```shell
#!/bin/bash

dst="172.19.0.10"
rs1="172.19.0.2"
rs2="172.19.0.3"
ip route del $dst/32
ip route add $dst/32 nexthop via $rs1 dev eth0 weight 1
while true; do
    nexthop=$(ip route show $dst/32 | awk '{print $3}')
    # nexthop=$(ip route show "$dst" | grep -oP "nexthop \K\S+")
    echo "to ${dst} via ${nexthop} now!"
    sleep 3
    
    # the requirements for blank is crazy!
    if [ "$nexthop" = "$rs1" ]; then
        new_nexthop="$rs2"
    else
        new_nexthop="$rs1"
    fi
    ip route del $dst/32
    ip route add $dst/32 nexthop via $new_nexthop dev eth0 weight 1
done
```

其实就是将到达 vip 的下一跳在几个 host（混布有 slb 和 app 的机器，以下简称 mix） 之间反复修改即可。

## NAT模式

版本 0.1~0.3 都采用了 full nat 模式，在当前混布的模式下不再合适，可能会导致数据包无穷循环。因为不对数据包做一些标记的话，xdp 程序无法区分是来自 client 的数据包还是来自另一个 slb 的包。我们采用 DR 模式，除了能避免循环问题以外，性能也更好，因为
1. 回包少了一跳
2. 包的修改少了，也不用重新计算 ip、tcp 校验和等

架构图如下，这里做了简化，client 和 mix 之间实际上是有 router/switch 的，但是我们采用上面的模拟脚本把 router/switch 路由功能也直接放 client 里面了。

![image.png](/img/bVc7ofx)

深蓝色表示请求，浅蓝色表示响应。
vip 采用了 ecmp，一次请求只会路由到一个 mix 上，mis 上的 slb 可能会把这个转发到本地 app（本文以 Nginx 为例） 或其它 mix，但是响应一定是从 mix 直接回去的，而不会再次经过其它 mix。

## 负载均衡算法

目前支持以下几种算法

- random
- round_roubin
- hash

本文不在 slb 集群中同步会话状态，所以只能选择 hash 算法，也就是不论请求路由到哪个 slb ，都会被转发到同一个 backend app。

## SLB 路由伪代码

```
if (dest_ip = local_ip){
	// 直接交给本机协议栈
	return
}
if (dest_ip = vip && dest_port = vport){
    使用负载均衡算法挑选一个 rs
	若RS就是本机，则 直接交给本机协议栈 并 return

	否则，将rs 的 mac 作为新包的 dst    
    此外保存 client 和 rs 的双向映射关系
    便于后续 路由直接 使用

	将本机 mac 作为新包的 src

	将新包扔出去重新路由
}else{
    报错，丢包
}
```


# 配置SLB和应用

Mix 的 Dockerfile 如下

```
FROM debian:bookworm
RUN apt-get update -y && apt-get upgrade -y \
    && apt install -y nginx procps bpftool iproute2 net-tools telnet kmod curl tcpdump

WORKDIR /tmp/
COPY src/slb /tmp/
COPY slb.conf /tmp/
```
这里修改镜像是因为我的宿主机 fedora:37 的 libc 版本是 2.36，而 debian:bullseye 对应的版本是 2.31 ，不能直接运行宿主机编译的可执行文件。

构建镜像并运行 app (这里是 nginx)

```
docker build -t mageek/mix:0.1 .

# in case you want to run a brand new container
docker rm mix1 mix2 -f

docker run -itd --name mix1 --hostname mix1 --privileged=true \
	--net south -p 8888:80 --ip 172.19.0.2 --mac-address="02:42:ac:13:00:02" \
	-v "$(pwd)"/rs1.html:/var/www/html/index.html:ro mageek/mix:0.1 nginx -g "daemon off;"

docker run -itd --name mix2 --hostname mix2 --privileged=true \
	--net south -p 9999:80 --ip 172.19.0.3 --mac-address="02:42:ac:13:00:03" \
	-v "$(pwd)"/rs2.html:/var/www/html/index.html:ro mageek/mix:0.1 nginx -g "daemon off;"

# check on host
docker ps
curl 127.0.0.1:8888
curl 127.0.0.1:9999

```

分别进入容器，配置 VIP，由于我们已经有模拟的路由协议了，所以在 mix 中配置好 vip 以后，要关闭 arp，避免影响 client 的包的路由

```
docker exec -it mix1 bash
docker exec -it mix2 bash

ifconfig lo:0 172.19.0.10/32 up
echo "1">/proc/sys/net/ipv4/conf/all/arp_ignore
echo "1">/proc/sys/net/ipv4/conf/lo/arp_ignore
echo "2">/proc/sys/net/ipv4/conf/all/arp_announce
echo "2">/proc/sys/net/ipv4/conf/lo/arp_announce
```

然后运行 slb 

```
# 启动 slb 并指定网卡和配置文件
./slb -i eth0 -c ./slb.conf

# in another terminal 
bpftool prog list
# bpftool prog show name xdp_lb  --pretty

# check global variables
# bpftool map list
# bpftool map dump name slb_bpf.rodata

# check attaching with 
ip link

```

日志直接在宿主机（整机一份）上看即可，不要开好几个终端（会导致日志不完整）

`bpftool prog tracelog`

此外，测试阶段可以直接在宿主机编译完成可执行文件后，拷贝到容器里(当然，前提是你已经创建好了这些容器和相关的网络)

```

docker start mix1 mix2 client

docker cp src/slb mix1:/tmp/ && \
docker cp slb.conf mix1:/tmp/ && \
docker cp src/slb mix2:/tmp/ && \
docker cp slb.conf mix2:/tmp/ && \
docker cp routing.sh client:/tmp/ 

```

# 测试

新起一个client容器

```
docker run -itd --name client --hostname client --privileged=true \
	--net south -p 10000:80 --ip 172.19.0.9 --mac-address="02:42:ac:13:00:09" \
	-v "$(pwd)"/routing.sh:/tmp/routing.sh mageek/mix:0.1 nginx -g "daemon off;"
```

进入 client 配置并运行以下路由脚本脚本

```shell
docker exec -it client bash

sh routing.sh
```

另开一个 client terminal 进行请求测试

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
```

我们可以在 client 里面压测一把，但是要注意压测时不要运行 routing.sh ，因为并发场景下存在 **“老路由刚被删，新路由尚未建立的中间态”** 的问题，导致请求失败。

```
apt-get install apache2-utils

# 并发 50，总请求数 5000
ab -c 50 -n 5000 http://172.19.0.10:80/

```


压测结果如下，可见都成功了

```
erver Software:        nginx/1.22.1
Server Hostname:        172.19.0.10
Server Port:            80

Document Path:          /
Document Length:        5 bytes

Concurrency Level:      50
Time taken for tests:   3.141 seconds
Complete requests:      5000
Failed requests:        0
Total transferred:      1170000 bytes
HTML transferred:       25000 bytes
Requests per second:    1591.81 [#/sec] (mean)
Time per request:       31.411 [ms] (mean)
Time per request:       0.628 [ms] (mean, across all concurrent requests)
Transfer rate:          363.75 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0   15   3.9     15      31
Processing:     5   16   4.7     16      48
Waiting:        0   11   4.4     10      34
Total:         17   31   3.6     30      60

Percentage of the requests served within a certain time (ms)
  50%     30
  66%     32
  75%     32
  80%     33
  90%     35
  95%     37
  98%     40
  99%     47
 100%     60 (longest request)

```

还可以增大并发数测试，并发最大理论值是我们存储 conntrack 条目的 back_map 数量最大值。超过这个并发数，会导致重新路由映射，可能导致 tcp reset。

# 下文预告
要想打造一个完整的 slb，还有许多工作要做，比如利用内核能力进行 mac 自动寻址、许多边界检查等。这都是后面要做的工作，欢迎大家一起参与 https://github.com/MageekChiu/xdp4slb/。
