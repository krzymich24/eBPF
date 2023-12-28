// firewall_kern.c

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdio.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rule);
    __uint(max_entries, 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, char[200]);
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} log_map SEC(".maps");

struct rule {
    char    name[64];
    int32_t action;
    int32_t protocol;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
};

int keylog = 0;

void loger(const char *str) {

    bpf_map_update_elem(&log_map, &keylog, str, BPF_ANY);
    keylog++;

    if(keylog == 100){
       keylog = 0; 
    }
}

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
            
            for (int i = 0; i < 10; i++) {
                
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

                } else if (key == 9){
                    char log_message[200];
                    int parameter1 = 42;

                    // Format the log message with parameters
                    snprintf(log_message, sizeof(log_message), "Passed ICMP packet with parameters: %d", parameter1);
                    loger(log_message);
                    bpf_printk("Passed ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;

                }
            }

        } else if  (ip_protocol == IPPROTO_TCP){
            struct iphdr *iph = data + nh_off;
            uint32_t src_ip = ntohl(iph->saddr);
			uint32_t dest_ip = ntohl(iph->daddr);

            // Extract source and destination ports
            void *transport_header = data + nh_off + sizeof(struct iphdr);
            if (transport_header + sizeof(struct tcphdr) > data_end) {
                return XDP_DROP;
            }

            struct tcphdr *tcph = transport_header;
            uint16_t src_port = ntohs(tcph->source);
            uint16_t dest_port = ntohs(tcph->dest);

            bpf_printk("Source Port: %u, to destination Port: %u\n", src_port, dest_port);

            struct rule *rule_entry;

            for (int i = 0; i < 10; i++) {
                
                uint32_t key = i;  
                rule_entry = (struct rule *)bpf_map_lookup_elem(&rule_map, &key);

                if (rule_entry) {

                    if (rule_entry->protocol == 6) {
                        uint32_t rule_src_ip = rule_entry->source_ip;
                        uint32_t rule_dest_ip = rule_entry->dest_ip;
                        uint16_t rule_src_port = rule_entry->src_port;
                        uint16_t rule_dest_port = rule_entry->dest_port;
                        
                        if ( (src_ip == rule_src_ip || rule_src_ip == 0) && (dest_ip == rule_dest_ip || rule_dest_ip == 0) && (src_port == rule_src_port || rule_src_port == 0) && (dest_port == rule_dest_port || rule_dest_port == 0 ) ) {
                            if (rule_entry->action == 1) {
                                bpf_printk("Blocked with rule: %u, TCP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
                                bpf_printk("Passed with rule: %u, TCP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_PASS;
							}
                        }

                    }

                } else if (key == 9){
                    bpf_printk("Passed TCP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;

                } 
                    
            }

        } else if (ip_protocol == IPPROTO_UDP){

            struct iphdr *iph = data + nh_off;
            uint32_t src_ip = ntohl(iph->saddr);
            uint32_t dest_ip = ntohl(iph->daddr);

            // Extract source and destination ports
            void *transport_header = data + nh_off + sizeof(struct iphdr);
            if (transport_header + sizeof(struct udphdr) > data_end) {
                return XDP_DROP;
            }

            struct udphdr *udph = transport_header;
            uint16_t src_port = ntohs(udph->source);
            uint16_t dest_port = ntohs(udph->dest);

            bpf_printk("SRC Port: %u, DEST Port: %u\n", src_port, dest_port);

            struct rule *rule_entry;

            for (int i = 0; i < 10; i++) {
                
                int key = i;  
                rule_entry = (struct rule *)bpf_map_lookup_elem(&rule_map, &key);

                if (rule_entry) {

                    if (rule_entry->protocol == 17) {
                        uint32_t rule_src_ip = rule_entry->source_ip;
                        uint32_t rule_dest_ip = rule_entry->dest_ip;
                        uint16_t rule_src_port = rule_entry->src_port;
                        uint16_t rule_dest_port = rule_entry->dest_port;

                        if ( (src_ip == rule_src_ip || rule_src_ip == 0) && (dest_ip == rule_dest_ip || rule_dest_ip == 0) && (src_port == rule_src_port || rule_src_port == 0) && (dest_port == rule_dest_port || rule_dest_port == 0 ) ) {
                            if (rule_entry->action == 1) {
                                bpf_printk("Blocked with rule: %u, UDP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
                                bpf_printk("Passed with rule: %u, UDP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_PASS;
							}
                        }

                    }

                } else if (key == 9){
                    bpf_printk("Passed UDP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;

                }

            }
            
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
