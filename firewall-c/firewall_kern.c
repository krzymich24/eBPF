// firewall_kern.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule);
    __type(value, struct rule);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_map SEC(".maps");

struct rule {
    char    name[64];
    int32_t action;
    int32_t protocol;
    uint32_t source_ip;
    uint32_t dest_ip;
    int16_t srcport;
    int16_t destport;
};

SEC("xdp")
int bpf_program1(struct __sk_buff *skb) {
    // Get the data pointer
    void *data = (void *)(long)skb->data;

    // Parse the Ethernet header
    struct ethhdr *eth = data;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
