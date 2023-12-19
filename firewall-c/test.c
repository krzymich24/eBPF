// firewall_kern.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <linux/icmp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
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

static inline uint8_t parse_ipv4(void *data, uint64_t nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end){
        return 0;
    }

    return iph->protocol;
}

SEC("xdp")
int bpf_program1(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    uint16_t h_proto;
    uint8_t ip_protocol;
    uint64_t nh_off = 0;
    nh_off = sizeof(*eth);
        
    if (data + nh_off  > data_end){
        return XDP_DROP;
    } 
    
    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IP)) { 
        
        struct iphdr *ip = data + sizeof(struct ethhdr);
        ip_protocol = parse_ipv4(data, nh_off, data_end);

        if (ip_protocol == IPPROTO_ICMP) {
            struct iphdr *iph = data + nh_off;
            uint32_t src_ip = ntohl(iph->saddr);
			uint32_t dest_ip = ntohl(iph->daddr);

            struct rule *rule_entry;
            
            for (int i = 0; i < 1024; i++) {
                
                int key = i;  
                rule_entry = (struct rule *)bpf_map_lookup_elem(&rule_map, &key);

                if (rule_entry) {

                    if (rule_entry->protocol == 1) {
                        uint32_t rule_src_ip = rule_entry->source_ip;
                        uint32_t rule_dest_ip = rule_entry->dest_ip;
                        if ( (src_ip == rule_src_ip || rule_src_ip == 0) && (dest_ip == rule_dest_ip || rule_dest_ip == 0) ) {
                            if (rule_entry->action == 1) {
                                bpf_printk("Blocked with rule: %u, ICMP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
                                bpf_printk("Passed with rule: %u, ICMP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_PASS;
							}
                        }

                    }

                } else if (key == 1023){
                    bpf_printk("Passed ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;

                } else{
                    
                    key++;

                }

            }

        } else if (ip_protocol == IPPROTO_TCP){

            return XDP_PASS;

        } else if (ip_protocol == IPPROTO_UDP){

            return XDP_PASS;
            
        }else{

            return XDP_PASS;
        
        }

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
