#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
// #include <linux/ip.h>
// #include <linux/udp.h>
// #include <linux/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "slb.skel.h"
#include "slb.h"
#include "linux/if_link.h"

// https://github.com/libbpf/libbpf-rs/issues/185
#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE
#define LINE_SIZE 256
#define LINE_ELEM_NUM 3

const static __u32 map_flags = BPF_ANY;
const static __u32 FIXED_INDEX = 0;

static struct env {
	bool verbose;
	char *interface;
	enum LB_ALG cur_lb_alg;
	__u32 max_conntrack;
	enum clear_mode cur_clear_mode;

	char *conf_path;
	struct host_meta vip;
	struct host_meta gip;
	__u8 back_num;
	__u32 local_ip;
	__u64 cur_cgp_id;
	struct host_meta backends[MAX_BACKEND];
	
} env;

const char *argp_program_version = "slb 0.4";
const char *argp_program_bug_address = "<mageekchiu@gmail.com>";
const char argp_program_doc[] =
"A software load balancing implemention based on ebpf/xdp.\n"
"\n"
"Not Production Ready! \n"
"\n"
"USAGE: ./slb [-v] [-i nic] [-a alg] [-m size] [-g cgroup_id] -c conf_path\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "interface", 'i', "nic", 0, "Interface to attach, default:eth0" },
	{ "alg", 'a', "lb_alg", 0, "Load balancing algorithm:random:1|round_robin:2|hash:3, default:hash" },
	{ "conf", 'c', "conf_path", 0, "Config about vip,backends" },
	{ "mx_con", 'm', "max_conntrack_size", 0, "max entry of conntrack table size,default:4096" },
	{ "clr_md", 'k', "clear_mode", 0, "how we clear conntrack entry: none_clear:1|just_local:2|group_cast:3|broad_cast:4, default:just_local" },
	{ "cgp_id", 'g', "cgroup_id", 0, "cgroup id, useful in container" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state){
	int no;
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interface = arg;
		break;
	case 'a':
		errno = 0;
		no = strtol(arg, NULL, 10);
		if (errno || no < 1 || no > 3) {
			fprintf(stderr, "Invalid alg: %s, must be in 1,2,3\n", arg);
			argp_usage(state);
		}
		env.cur_lb_alg = ( enum LB_ALG ) no;
		break;
	case 'm':
		errno = 0;
		no = strtol(arg, NULL, 10);
		if (errno || no < 1 ) {
			fprintf(stderr, "Invalid conntrack size: %s\n", arg);
			argp_usage(state);
		}
		env.max_conntrack = no;
		break;
	case 'k':
		errno = 0;
		no = strtol(arg, NULL, 10);
		if (errno || no < 1 || no > 4) {
			fprintf(stderr, "Invalid mode: %s, must be in 1,2,3,4\n", arg);
			argp_usage(state);
		}
		env.cur_clear_mode = (enum clear_mode ) no;
		break;
	case 'g':
		errno = 0;
		no = strtol(arg, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid cgroup_id: %s\n", arg);
			argp_usage(state);
		}
		env.cur_cgp_id = no;
		break;
	case 'c':
		env.conf_path = arg;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo){
	exiting = 1;
}

static bool forge_header(const ce *e,__u32 ip, __u16 port){

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
    	fprintf(stderr,"error creating socket");
    	return false;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    // addr.sin_addr.s_addr = inet_addr(multi_group);
    // addr.sin_port = htons(host_port);
	addr.sin_addr.s_addr = ip;
    addr.sin_port = port;

	int cnt = sendto(fd,
            e,sizeof(e),
            0,
            (struct sockaddr*) &addr,sizeof(addr)
        );
	if (cnt < 0) {
    	fprintf(stderr,"error sending msg");
    	return false;
	}
	return true;
}

static bool do_multcast(const ce *e){
	return forge_header(e,env.gip.ip_int,env.gip.port);
}

static bool do_broadcast(const ce *e){
	return true;
}

static int handle_event(void *ctx, void *data, size_t data_sz){
	// const struct event *e = data;
	// fprintf(stderr, "Mix:%u, total_bits: %llu, local_bits: %llu\n",env.local_ip,e->total_bits,e->local_bits);
	// return 0;
	const ce *e = data;
	bool sent = false;
	// do the casting
	if(env.cur_clear_mode == group_cast){
		sent = do_multcast(e);
	}else if(env.cur_clear_mode == broad_cast){
		sent = do_broadcast(e);
	}
	fprintf(stderr, "Mix:%u, %u:%u is released,sent:%d\n",
		env.local_ip,e->ip,e->port,sent);
	return 0;
}

static void populate_defaults(){
	if(!env.interface){
		env.interface = "eth0";
	}
	fprintf(stderr, "interface %s\n",env.interface);

	if(!env.cur_lb_alg){
		env.cur_lb_alg = lb_n_hash;
	}
	fprintf(stderr, "cur_lb_alg %d\n",env.cur_lb_alg);

	if(!env.max_conntrack){
		env.max_conntrack = MAX_CONNTRACK;
	}
	fprintf(stderr, "max_conntrack %d\n",env.max_conntrack);

	if(!env.cur_clear_mode){
		env.cur_clear_mode = just_local;
	}
	fprintf(stderr, "cur_clear_mode %d\n",env.cur_clear_mode);

	if(!env.cur_cgp_id){
		env.cur_cgp_id = 0;
	}
	fprintf(stderr, "cur_cgp_id %llu\n",env.cur_cgp_id);
}

static int parse_conf(){
	if(!env.conf_path){
		fprintf(stderr, "Missing conf_path\n");
		return 1;
	}
	fprintf(stderr, "conf_path %s\n",env.conf_path);

    FILE *fp = fopen(env.conf_path, "r");
    if (!fp){
		fprintf(stderr, "Error opening config file %s!\n",env.conf_path);
        return 1;
    }

	int err = 0;
    char line_buff[LINE_SIZE];
	__u32 line_num = 0;
	__u32 backend_num = 0;
    while (fgets(line_buff, sizeof(line_buff), fp) != NULL){
		line_num++;
		// remove trailing \n https://stackoverflow.com/questions/2693776/removing-trailing-newline-character-from-fgets-input
		line_buff[strcspn(line_buff, "\n")] = 0;
        char *token = strtok(line_buff, ",");
		char *meta[LINE_ELEM_NUM];
		__u32 i = 0;
		for(;i < LINE_ELEM_NUM && token != NULL; i++,token = strtok(NULL, ",") ){
			meta[i] = token;
		}
		if(i != LINE_ELEM_NUM){
			fprintf(stderr, "Not enough config in line %s, element num %u!\n",line_buff,i);
        	err = 1;
			break;
		}

		errno = 0;
		__u16 port = strtol(meta[2], NULL, 10);
		if (errno || port < 1 || port > 65535) {
			fprintf(stderr, "error port %s, errno %d!\n",meta[3],errno);
        	err = 1;
			break;
		}

		struct host_meta hm;
		// if ip is array ,I dont need to do the following 3 line,
		// a simple memcpy wiil do
		int size = sizeof(char) * (strlen(meta[1]) + 1);
		hm.ip = malloc(size);
		memcpy(hm.ip, meta[1], size);

		__u32 ip = inet_addr(hm.ip);
		hm.ip_int = ip;
		hm.port = htons(port);

		if (strcmp(meta[0], "vip") == 0){
			env.vip = hm;
		}
		else if (strcmp(meta[0], "backend") == 0){
			env.backends[backend_num++] = hm;
		}
		else if (strcmp(meta[0], "gip") == 0){
			env.gip = hm;
		}
		else{
			fprintf(stderr, "Wrong element %s in %s, on line %u!\n",meta[0],line_buff,line_num);
        	err = 1;
			break;
		}
		fprintf(stderr, "type: %s, ip: %s--%s--%u--%u,\
port: %s--%u \n",
			meta[0],meta[1],hm.ip,ip,hm.ip_int,
			meta[2],hm.port);

    }
	if(line_num < 3 || backend_num < 1){
		fprintf(stderr, "Not enough config in file %s!,line_num %u,backend_num %u\n",env.conf_path,line_num,backend_num);
        err = 1;
	}
	env.back_num = backend_num;
	fprintf(stderr, "config: back_num\t%d\n",env.back_num);
	fprintf(stderr, "config: vip\t %u \n",env.vip.ip_int);

    fclose(fp);

	return err;
}
static int healthz_tcp(__u32 ip, __u16 port){
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
		fprintf(stderr, "error socket creating: \n");
        return 1;
    }

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
static int parse_local(){
	// ip, no clear file to read
	// awk '/32 host/ { print f } {f=$2}' <<< "$(</proc/net/fib_trie)"
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, env.interface, IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFADDR, &ifr) < 0){
		fprintf(stderr, "Error reading ip addr %s!\n",env.interface);
        return 1;
	}
	/* display result */
	struct in_addr ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	// env.local_ip = htonl(ip_addr.s_addr);
	// net edian already
	env.local_ip = (ip_addr.s_addr);
	printf("Local ip is %s, %u-%u\n", inet_ntoa(ip_addr),ip_addr.s_addr,env.local_ip);
	close(fd);

	return 0;
}

int main(int argc, char **argv){

	int err;
	struct ring_buffer *rb = NULL;
	struct slb_bpf *skel;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	populate_defaults();
	err = parse_local();
	if (err)
		return err;
	err = parse_conf();
	if (err)
		return err;
	if(env.cur_clear_mode == group_cast && env.gip.ip == 0){
		fprintf(stderr, "group ip must be specified\n");
		return -1;
	}
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	/* Load and verify BPF programs */
	skel = slb_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF programs  */
	skel->rodata->cur_cgp_id = env.cur_cgp_id;
	skel->rodata->NUM_BACKENDS = env.back_num;
	skel->rodata->cur_lb_alg = env.cur_lb_alg;
	skel->rodata->local_ip = env.local_ip;
	skel->rodata->cur_clear_mode = env.cur_clear_mode;
	bpf_map__set_max_entries(skel->maps.conntrack_map, env.max_conntrack);
	
	// // accessible
	fprintf(stderr, "alg %u \n",skel->rodata->cur_lb_alg);
	fprintf(stderr, "vip %s \n",env.vip.ip);
	fprintf(stderr, "gip %s \n",env.gip.ip);
	fprintf(stderr, "local ip %u \n",skel->rodata->local_ip);
	fprintf(stderr, "backends num: %u \n",skel->rodata->NUM_BACKENDS);
	
	/* Load & verify BPF programs */
	err = slb_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach  */
	if(env.cur_clear_mode > none_clear){
		fprintf(stderr, "Attaching conntrack clearing, mode: %u,cgroup:%llu\n",
			env.cur_clear_mode, env.cur_cgp_id);
		
		err = slb_bpf__attach(skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto cleanup;
		}

		// // Operation not supported
		// errno = 0;
		// bpf_program__attach(skel->progs.rele_hdl);
		// if (errno ) {
		// 	fprintf(stderr, "Invalid mode: %s\n", strerror(errno));
		// }

		// int cgid = bpf_get_current_cgroup_id();
		// bpf_program__attach_cgroup(skel->progs.rele_hdl,cgid);
	
		// bpf_prog_attach(bpf_program__fd(skel->progs.rele_hdl),"",);
	}
	

	int ifindex = if_nametoindex(env.interface);
	if(!ifindex){
		fprintf(stderr, "Failed to find nic %s \n",env.interface);
		goto cleanup;
	}
	int prog_fd = bpf_program__fd(skel->progs.xdp_lb);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS,NULL);
	// // better way to attach; but mot working in docker
	// bpf_program__attach_xdp(skel->progs.xdp_lb,ifindex);
	if (err) {
		fprintf(stderr, "Failed to attach program to intraface\n");
		goto cleanup;
	}

	// must be after attaching or "Error updating vip_map 4294967295, code 9, reaon Bad file descriptor!"
	int vip_map_fd = bpf_map__fd(skel->maps.vip_map);
	int backends_map_fd = bpf_map__fd(skel->maps.backends_map);
	if(!vip_map_fd || 
		!backends_map_fd){
		fprintf(stderr, "Failed to find config map\n");
		return 1;
	}
	errno = 0;
	err = bpf_map_update_elem(vip_map_fd, &FIXED_INDEX, &(env.vip), map_flags);
	if (err){
		fprintf(stderr, "Error updating vip_map %u, code %u, reaon %s!\n",vip_map_fd, errno,strerror(errno));
        return 1;
    }
	if(env.cur_clear_mode == group_cast){
		int gip_map_fd = bpf_map__fd(skel->maps.gip_map);
		if(!gip_map_fd){
			fprintf(stderr, "Failed to find gip config map\n");
			return 1;
		}
		errno = 0;
		err = bpf_map_update_elem(gip_map_fd, &FIXED_INDEX, &(env.gip), map_flags);
		if (err){
			fprintf(stderr, "Error updating vip_map %u, code %u, reaon %s!\n",vip_map_fd, errno,strerror(errno));
			return 1;
		}
	}
	for(int i = 0;i < env.back_num;i++){
		int error = healthz_tcp(env.backends[i].ip_int,env.backends[i].port);
		if(error){
			fprintf(stderr, "Error checking backend %u:%u!\n",
			env.backends[i].ip_int,env.backends[i].port);
			// continue;
		}
		err = bpf_map_update_elem(backends_map_fd, &i, &(env.backends[i]), map_flags);
		if (err){
			fprintf(stderr, "Error updating backends_map %u, code %u, reaon %s!\n",backends_map_fd, errno,strerror(errno));
			return 1;
		}
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	fprintf(stderr, "Mix \t total_bits \t local_bits\n");
	while (!exiting) {
		fprintf(stderr, "%u \t %llu \t %llu\n",env.local_ip,skel->bss->total_bits,skel->bss->local_bits);
		err = ring_buffer__poll(rb, RING_BUFF_TIMEOUT);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	bpf_xdp_detach(ifindex, XDP_FLAGS,NULL);
	ring_buffer__free(rb);
	slb_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
