#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "slb.h"
#include "slb.skel.h"
#include "linux/if_link.h"

#define XDP_FLAGS XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE

static struct env {
	bool verbose;
	char *interface;
} env;

const char *argp_program_version = "slb 0.2";
const char *argp_program_bug_address = "<mageekchiu@gmail.com>";
const char argp_program_doc[] =
"A software load balancing implemention based on ebpf/xdp.\n"
"\n"
"Not Production Ready! \n"
"\n"
"USAGE: ./slb [-v] [-i nic]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "interface", 'i', "nic", 0, "Interface to attach, default:eth0" },
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


int main(int argc, char **argv){

    struct slb_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	if(!env.interface){
		env.interface = "eth0";
	}
	fprintf(stderr, "interface %s\n",env.interface);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);

	/* Load and verify BPF application */
	skel = slb_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code  */


	/* Load & verify BPF programs */
	err = slb_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach  */
	char *nic = env.interface;
	// char *nic = "enp0s1";
	// char *nic = "eth0";
	int ifindex = if_nametoindex(nic);
	if(!ifindex){
		fprintf(stderr, "Failed to find nic %s \n",nic);
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

	/* Attach  */
	// err = slb_bpf__attach(skel);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach BPF skeleton\n");
	// 	goto cleanup;
	// }

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
