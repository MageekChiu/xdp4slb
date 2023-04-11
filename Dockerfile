# 这里修改镜像是因为我的宿主机 fedora:37 的 libc 版本是 2.36，
# debian:bullseye 对应的版本是 2.31 ，不能直接运行宿主机编译的可执行文件。
FROM fedora:37
RUN dnf install -y file binutils procps bpftool iproute net-tools telnet kmod curl tcpdump

WORKDIR /tmp/
COPY src/slb /tmp/