#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "slb.h"
#include "slb.skel.h"
#include "linux/if_link.h"

#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE
#define LINE_SIZE 256
#define LINE_ELEM_NUM 4

static struct env {
	bool verbose;
	char *interface;
	enum LB_ALG cur_lb_alg;

	char *conf_path;
	struct host_meta slb;
	struct host_meta vip;
	// flexible array member must be at end of struct
	// struct host_meta backends[];
	struct host_meta backends[MAX_BACKEND];
	
} env;

const char *argp_program_version = "slb 0.3";
const char *argp_program_bug_address = "<mageekchiu@gmail.com>";
const char argp_program_doc[] =
"A software load balancing implemention based on ebpf/xdp.\n"
"\n"
"Not Production Ready! \n"
"\n"
"USAGE: ./slb [-v] [-i nic] -c conf_path\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "interface", 'i', "nic", 0, "Interface to attach, default:eth0" },
	{ "alg", 'a', "lb_alg", 0, "Load balancing algorithm:random:1|round_robin:2|hash:3, default:hash" },
	{ "conf", 'c', "conf_path", 0, "Config about vip,slb,backends" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state){
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'i':
		env.interface = arg;
		break;
	case 'a':
		errno = 0;
		int no = strtol(arg, NULL, 10);
		if (errno || no < 1 || no > 3) {
			fprintf(stderr, "Invalid alg: %s, must be in 1,2,3\n", arg);
			argp_usage(state);
		}
		env.cur_lb_alg = ( enum LB_ALG ) no;
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

static void populate_defaults(){
	if(!env.interface){
		env.interface = "eth0";
	}
	fprintf(stderr, "interface %s\n",env.interface);

	if(!env.cur_lb_alg){
		env.cur_lb_alg = lb_n_hash;
	}
	fprintf(stderr, "cur_lb_alg %d\n",env.cur_lb_alg);
}

static int parse_conf(){
	if(env.conf_path){
		fprintf(stderr, "Missing conf_path\n");
		return 1;
	}

    FILE *fp = fopen(env.conf_path, "r");
    if (!fp){
		fprintf(stderr, "Error opening file %s!\n",env.conf_path);
        return 1;
    }

	int err = 0;
    char line_buff[LINE_SIZE];
	__u32 line_num = 0;
	__u32 backend_num = 0;
    while (fgets(line_buff, sizeof(line_buff), fp) != NULL){
		line_num++;
        char *token = strtok(line_buff, ",");
		// struct host_meta hm = {0};
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
		__u16 port = strtol(meta[3], NULL, 10);
		if (errno || port < 1 || port > 65535) {
			fprintf(stderr, "error port %s!\n",meta[3]);
        	err = 1;
			break;
		}

		__u32 ip = inet_addr(meta[1]);

		__u8 mac_addr[ETH_ALEN];
		__u32 values[ETH_ALEN];
		int j;

		if( ETH_ALEN == sscanf(meta[2], "%x:%x:%x:%x:%x:%x%*c",
			&values[0], &values[1], &values[2],
			&values[3], &values[4], &values[5]) ){
			for( j = 0; j < ETH_ALEN; ++j )
				mac_addr[j] = (__u8) values[j];
		}else{
			/* invalid mac */
			fprintf(stderr, "error mac %s!\n",meta[2]);
        	err = 1;
			break;
		}

		struct host_meta hm;
		hm.ip = meta[1];
		hm.ip_int = htonl(ip);
		// error
		// hm.mac_addr = mac_addr;
		memcpy(hm.mac_addr, mac_addr, ETH_ALEN);
		hm.port = htons(port);

		if (strcmp(meta[0], "slb") == 0){
			env.slb = hm;
		} 
		else if (strcmp(meta[0], "vip") == 0){
			env.vip = hm;
		}
		else if (strcmp(meta[0], "backend") == 0){
			env.backends[backend_num++] = hm;
		}
		else{
			fprintf(stderr, "Wrong element %s in %s, on line %u!\n",meta[0],line_buff,line_num);
        	err = 1;
			break;
		}
    }
	if(line_num < 3 || backend_num < 1){
		fprintf(stderr, "Not enough config in file %s!,line_num %u,backend_num %u\n",env.conf_path,line_num,backend_num);
        err = 1;
	}

    fclose(fp);

	return err;
}

int main(int argc, char **argv){

	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	err = parse_conf();
	if (err)
		return err;
	populate_defaults();

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	/* Load and verify BPF programs */
	struct slb_bpf *skel = slb_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF programs  */
	skel->rodata->cur_lb_alg = env.cur_lb_alg;

	/* Load & verify BPF programs */
	err = slb_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach  */
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

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	/* Clean up */
	bpf_xdp_detach(ifindex, XDP_FLAGS,NULL);
	slb_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
