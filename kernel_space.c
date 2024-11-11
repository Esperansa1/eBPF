
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "tc.h"
#include <stdbool.h>

//#include <linux/if_ether.h>
#define ETH_ALEN 6
#define ETH_P_IP    0x0800

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

#define PORT_AMOUNT 20

#define htons bpf_htons
#define ntohl bpf_ntohl
#define ntohs bpf_ntohs


pid_t my_pid = 0;

// Create ringbuf structure 
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024);
} rb SEC(".maps");

// Create array structure as ports
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PORT_AMOUNT);
    __type(value, u16);
    __type(key, u32);
} ports SEC(".maps");

// Create hashmap structure as packet_stats 
struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 1024);
        __type(key, __u32);
        __type(value, struct value);
} packet_stats SEC(".maps");

// gets srcip, bytes and updates packet_stats hash
static void update_stats(__u32 srcip, __be16 bytes)
{
    struct value *value = bpf_map_lookup_elem(&packet_stats, &srcip);

    if (value) {
            __sync_fetch_and_add(&value->packets, 1);
            __sync_fetch_and_add(&value->bytes, bytes);
    } else {
            struct value newval = { 1, bytes, srcip };
            bpf_map_update_elem(&packet_stats, &srcip, &newval, BPF_NOEXIST);
    }
}

// gets a ethhdr and data_end and returns if is a ipv4 header
struct iphdr* is_ipv4(struct ethhdr *eth, void *data_end) 
{
    struct iphdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == htons(ETH_P_IP)) {
        iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

// checks if the given header is a udp header
struct udphdr* is_udp(void *iph, u8 hdr_sz, void *data_end)
{
    struct udphdr *udph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*udph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    }

    if (proto == IPPROTO_UDP) {
        udph = (struct udphdr*)((void*)iph + hdr_sz);
    }
    return udph; 
}

// checks if the given header is a tcp header
struct tcphdr* is_tcp(void *iph, u8 hdr_sz, void *data_end)
{
    struct tcphdr *tcph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*tcph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    }

    if (proto == IPPROTO_TCP) {
        tcph = (struct tcphdr*)((void*)iph + hdr_sz);
    }
    return tcph;
}

// checks if a given port is allowed, if entered ALL_PORTS_ALLOWED number (default -1 as in ALL_PORTS_ALLOWED variable), all ports will be open
int is_port_allowed(int target_port){
    u32 i = 0;
    for (i = 0; i < PORT_AMOUNT; i++) {
        u16 *port;
        u32 key = i;
        port = bpf_map_lookup_elem(&ports, &key);

        // check if the packet's port is within the allowed ports or the user allowed all ports (default port -1)
        if (port && (target_port == *port || *port == (u16)ALL_PORTS_ALLOWED)) {  // comparison of u16 and int is always false so cast to u16
            return true;
        }
    }
    return false;
}

// Handles packet traffic and passes it over to the userspace using the ringbuf and the bpf map
SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    pid_t tgid = BPF_CORE_READ(t, tgid); // t->tgid
    pid_t pid = BPF_CORE_READ(t, pid); // t->pid
    if (tgid == my_pid) {
        return TC_ACT_OK; // No need to handle my own traffic
    }

    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;
    struct iphdr *iph = is_ipv4(eth, data_end);

    struct tc_evt *evt = NULL;

    // gets the ringbuf memory allocation pointer
    evt = bpf_ringbuf_reserve(&rb, sizeof(*evt), 0);
    if (!evt) {
        goto rb_err;
    }
    __builtin_memset(evt, 0, sizeof(*evt));
    evt->eth_type = htons(BPF_CORE_READ(eth, h_proto));
    bpf_probe_read_kernel_str(evt->comm, TASK_LEN, BPF_CORE_READ(t, group_leader, comm));
    evt->tgid = tgid;
    evt->pid = pid;
    evt->pkt_state = BLOCKED; // Block packet by default (for showing in C userspace)

    int rc = TC_ACT_SHOT; // Drop the packet by default

    if (iph) {
        u8 hdr_sz = sizeof(*iph);
        struct udphdr *udph = is_udp(iph, hdr_sz, data_end);
        struct tcphdr *tcph = is_tcp(iph, hdr_sz, data_end);

        if (tcph) {
            evt->ip.ipp = TCP_V4;
            evt->ip.port = ntohs(tcph->dest);
        } else if(udph) {
            evt->ip.ipp = UDP_V4;
            evt->ip.port = ntohs(udph->dest);
        }else{
            goto err;
        }

        u32 daddr = iph->daddr;
        u32 saddr = iph->saddr;

        if(is_port_allowed(evt->ip.port)){

            evt->pkt_state = ALLOWED;
            rc = TC_ACT_OK;

            bpf_probe_read_kernel(&evt->ip.daddr.ipv4_daddr, sizeof(evt->ip.daddr.ipv4_daddr), &daddr);
            bpf_probe_read_kernel(&evt->ip.saddr.ipv4_saddr, sizeof(evt->ip.saddr.ipv4_saddr), &saddr);

            // Add stats to the destination on the condition that the packet is within the allowed ports
            update_stats(daddr, iph->tot_len);
        }
    }

    bpf_ringbuf_submit(evt, 0);
    evt = NULL;
    err:
        if (evt) bpf_ringbuf_discard(evt, 0);
    rb_err:
        return TC_ACT_OK; // Need to return rc value here but do not want to block any packets to not block myself out of SSH
}

char LICENSE[] SEC("license") = "GPL";