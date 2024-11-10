#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "tc.h"
#include "tc.skel.h"

static volatile bool exiting = false;

char* print_proto(enum ip_proto ipp)
{
    switch(ipp) {
        case TCP_V4:
            return "TCP ipv4";
        case UDP_V4:
            return "UDP ipv4";
        case TCP_V6:
            return "TCP ipv6";
        case UDP_V6:
            return "UDP ipv6";
        default:
            return "OTHER";
    }
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}
void allow_port(int map_fd, uint16_t port)
{
    static uint32_t key = 0;
    bpf_map_update_elem(map_fd, &key, &port, 0);
    key++;
}

static void print_ipv4addr(u_int8_t addr[]){
    char addr_string[15];
    memset(addr_string, 0, sizeof(addr_string));
    snprintf(addr_string, sizeof(addr_string), "%d.%d.%d.%d",
        addr[0],
        addr[1],
        addr[2],
        addr[3]);
    printf("%s\n", addr_string);
}


static int handle_evt(void *ctx, void *data, size_t sz)
{
    struct tc_evt *evt = data;

    if (evt->pkt_state == ALLOWED) printf("ALLOWED ");
    else {
        // printf("BLOCKED ");
        return 0;
    }

    if (evt->eth_type == ETH_P_IP || evt->eth_type == ETH_P_IPV6) {
        // fflush(stdout);
        printf("comm: %s\n", evt->comm);
        printf("tgid %d :: pid %d\n", evt->tgid, evt->pid);
        if (evt->ip.ipp == TCP_V4 || evt->ip.ipp == UDP_V4) {
            printf("dest: ");
            print_ipv4addr(evt->ip.daddr.ipv4_daddr);

            printf("port: %d\n", evt->ip.port);
        }
        printf("protocol: %s\n", print_proto(evt->ip.ipp));
    }
    
    printf("\n");
    fflush(stdout);
    return 0;
}

static void sig_handler(int sig)
{
    exiting = true;
}


int main(int argc, char **argv)
{
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 2, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);
    bump_memlock_rlimit();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct tc *skel = tc__open_and_load();
    skel->bss->my_pid = getpid();

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;
    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;

    bpf_tc_attach(&hook, &opts);
    
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);

    int map_fd = bpf_map__fd(skel->maps.ports);

    if(argc == 1){
        allow_port(map_fd, ALL_PORTS_ALLOWED);
    }

    for (int i = 1; i < argc; i++) {
        printf("%s\n", argv[i]);
        int port = atoi(argv[i]);
        allow_port(map_fd, port);
        printf("Allowed port %d\n", port);
    }

    while(!exiting) {
        ring_buffer__poll(rb, 1000);
    }

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);
    
    return 0;
}