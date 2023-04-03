FROM debian:bullseye
# modify source to get faster installation
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list \
    && apt-get update -y && apt-get upgrade -y \
    && apt install -y procps bpftool iproute2 net-tools telnet kmod curl tcpdump

WORKDIR /tmp/
COPY slb.bpf.o /tmp/
