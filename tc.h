#ifndef __TC_H__
#define __TC_H__

#define TASK_LEN 16

enum ip_proto {
    TCP_V4,
    TCP_V6,
    UDP_V4,
    UDP_V6,
};

enum pkt_state {
    BLOCKED,
    ALLOWED,
};

struct ip_info {
    enum ip_proto ipp;
     union {
        uint8_t ipv6_daddr[16];
        uint8_t ipv4_daddr[4];
    } daddr;

    union {
        uint8_t ipv6_saddr[16];
        uint8_t ipv4_saddr[4];
    } saddr;

    uint16_t port;
};

struct tc_evt {
    enum pkt_state pkt_state;
    pid_t tgid;
    pid_t pid;
    char comm[TASK_LEN];
    uint16_t eth_type;
    struct ip_info ip;
};

struct value {
    __u64 packets;
    __u64 bytes;
    __u32 addr;


};

#endif 