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
int packet_stats_fd;

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

static void print_ipv6addr(u_int32_t addr[]){
    char addr_string[15];
    memset(addr_string, 0, sizeof(addr_string));
    snprintf(addr_string, sizeof(addr_string), "%d.%d.%d.%d",
        addr[0],
        addr[1],
        addr[2],
        addr[3]);
    printf("%s\n", addr_string);
}

static void display_packet_statistics(){
        __u32 *cur_key = NULL;
        __u32 next_key;
        struct value value;
        int err;
        for (;;) {
                err = bpf_map_get_next_key(packet_stats_fd, cur_key, &next_key);
                if (err)
                        break;

                bpf_map_lookup_elem(packet_stats_fd, &next_key, &value);
                printf("IP: %08x", *cur_key);
                printf("Packet count: %llu", value.packets);
                printf("Total bytes: %llu", value.bytes);

                // Use key and value here

                cur_key = &next_key;
        }
}

static int handle_evt(void *ctx, void *data, size_t sz)
{
    display_packet_statistics();
    struct tc_evt *evt = data;

    if (evt->pkt_state == ALLOWED) printf("ALLOWED ");
    else printf("BLOCKED");

    if (evt->eth_type == ETH_P_IP || evt->eth_type == ETH_P_IPV6) {
        // fflush(stdout);
        printf("comm: %s\n", evt->comm);
        printf("tgid %d :: pid %d\n", evt->tgid, evt->pid);
        if (evt->ip.ipp == TCP_V4 || evt->ip.ipp == UDP_V4) {
            printf("dest: ");
            print_ipv4addr(evt->ip.daddr.ipv4_daddr);
            
            printf("source: ");
            print_ipv4addr(evt->ip.saddr.ipv4_saddr);

        } else {
            printf("dest: ");
            char addr[30];
            char a[6];
            memset(addr, 0, sizeof(addr));
            for (int i = 0; i < 14; i+=2) {
                snprintf(a, 6, "%02x%02x:",
                    evt->ip.daddr.ipv6_daddr[i],
                    evt->ip.daddr.ipv6_daddr[i+1]);
                strncat(addr, a, 6);
            }
            snprintf(a, 6, "%02x%02x",
                evt->ip.daddr.ipv6_daddr[14],
                evt->ip.daddr.ipv6_daddr[15]);
            strncat(addr, a, 6);
            printf("%s\n", addr);
        }
        // printf("port: %d\n", evt->ip.port);
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
    

    packet_stats_fd = bpf_map__fd(skel->maps.packet_stats);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_evt, NULL, NULL);
    // struct ring_buffer *packet_stats = ring_buffer__new(bpf_map__fd(skel->maps.rb), display_packet_statistics, NULL, NULL);


    while(!exiting) {
        ring_buffer__poll(rb, 1000); // READ ABOUT ME
        // ring_buffer__poll(packet_stats, 1000)
    }

    opts.flags = opts.prog_id = opts.prog_fd = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);

    printf("%d -- %d\n", dtch, dstr);
    
    return 0;
}