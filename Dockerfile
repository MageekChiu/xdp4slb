FROM debian:bookworm
RUN apt-get update -y && apt-get upgrade -y \
    && apt install -y nginx procps bpftool iproute2 net-tools telnet kmod curl tcpdump

WORKDIR /tmp/
COPY src/slb /tmp/
COPY slb.conf /tmp/