// firewall_kern.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

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
int bpf_program1(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    __u16 h_proto;
    uint8_t ip_protocol;
        
    if (data + sizeof(struct ethhdr) > data_end){ // This check is necessary to pass verification
        return XDP_DROP;
    } 
                
        
    h_proto = eth->h_proto;
    if (h_proto == htons(ETH_P_IP)) { 
        struct iphdr *ip = data + sizeof(struct ethhdr);
        ip_protocol = ip->protocol;
        return XDP_PASS;
    } else if (h_proto == htons(ETH_P_IPV6)){
        struct ipv6hdr *ipv6 = data + sizeof(struct ethhdr);
		return XDP_PASS;
	} else if (h_proto == htons(ETH_P_ARP)){
        struct arphdr *arp = data + sizeof(struct ethhdr);
		return XDP_PASS;
	} else if (h_proto == htons(ETH_P_RARP)){
        struct arphdr *rarp = data + sizeof(struct ethhdr);
		return XDP_PASS;
	}

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
