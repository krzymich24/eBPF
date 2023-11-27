package main

import (
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/iovisor/gobpf/bcc"
)


/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct rule {
    int32_t action;
    int32_t protocol;
	int32_t source;
    int32_t destination;
    int16_t srcport;
    int16_t destport;
};

struct rulekey {
    int32_t index;
    int32_t protocol;
};

// Change from BPF_HASH to BPF_ARRAY
BPF_ARRAY(rule_map, struct rule, 3);
BPF_HASH(rule_keys, int32_t, int32_t); 

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end){
        return 0;
    }

    return iph->protocol;
}

int xdp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr *eth = data;

    int rc = RETURNCODE;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    int protocol_number;
    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end){
        return rc;
    }

    h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);

        if (data + nh_off > data_end){
            return rc;    
        }

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
        struct vlan_hdr *vhdr;
        vhdr = data + nh_off;
        nh_off += sizeof(struct vlan_hdr);

        if (data + nh_off > data_end){
            return rc; 
        }

        h_proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (h_proto == htons(ETH_P_IP)) {
        int protocol_number = parse_ipv4(data, nh_off, data_end);
        bpf_trace_printk("Protocol_number: %u\n", protocol_number);

        if (protocol_number == IPPROTO_ICMP) {
            bpf_trace_printk("IPPROTO_ICMP");
            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;
			u32 dest_ip = iph->daddr;

			// Declare rule_entry outside the if block
            struct rule *rule_entry;

            // Iterate over all rules for the specific protocol
            struct rulekey rule_key = {.index = protocol_number};
            int *value;

            // Iterate through rules
            for (int i = 0; i < 3; i++) {
                rule_key.index = i;
                value = rule_keys.lookup(&rule_key);
                if (value && *value == protocol_number) {
                    // Found a matching value in the hash
                    bpf_trace_printk("Value found in rule_keys for index %d: %d\n", i, *value);

                    // Look up the rule in the rule_map
                    rule_entry = rule_map.lookup(&rule_key);
                    bpf_trace_printk("rule_entry: %u\n", rule_entry);

					if (rule_entry) {
						bpf_trace_printk("Entered rule: %u\n", rule_entry);
						bpf_trace_printk("IP packet: source IP: %u, destination IP: %u\n", src_ip, dest_ip);
                        bpf_trace_printk("In rule: source IP: %u, destination IP: %u\n", rule_entry->source, rule_entry->destination);

						if ((rule_entry->source == 0||src_ip == rule_entry->source) && (dest_ip == rule_entry->destination||rule_entry->destination == 0)){
							bpf_trace_printk("Processed source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
							if (rule_entry->action == 1) {
								bpf_trace_printk("Blocked with rule: %u, ICMP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
								bpf_trace_printk("Passed with rule: %u, ICMP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_PASS;
							}
						}else{
                            if (i < 2){
                                bpf_trace_printk("Checked rule:%u. Checking next rule: %u\n", i ,i+1); 
                            } else {
                                bpf_trace_printk("Checked rule:%u. End of rule for ICMP protocol", i); 
                            }
							
						}
					}
				} else if (i == 2){
                    bpf_trace_printk("No matching rule for src and dest. Passed ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;
                }
			}

        } else if (protocol_number == IPPROTO_TCP) {
			bpf_trace_printk("IPPROTO_TCP");
            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;
			u32 dest_ip = iph->daddr;

            // Extract source and destination ports
            void *transport_header = data + nh_off + sizeof(struct iphdr);
            if (transport_header + sizeof(struct tcphdr) > data_end) {
                return rc;
            }

            struct tcphdr *tcph = transport_header;
            u16 src_port = ntohs(tcph->source);
            u16 dest_port = ntohs(tcph->dest);

			// Declare rule_entry outside the if block
            struct rule *rule_entry;

            // Iterate over all rules for the specific protocol
            struct rulekey rule_key = {.index = protocol_number};
            int *value;

            // Iterate through rules
            for (int i = 0; i < 3; i++) {
                rule_key.index = i;
                value = rule_keys.lookup(&rule_key);
                if (value && *value == protocol_number) {
                    // Found a matching value in the hash
                    bpf_trace_printk("Value found in rule_keys for index %d: %d\n", i, *value);

                    // Look up the rule in the rule_map
                    rule_entry = rule_map.lookup(&rule_key);
                    bpf_trace_printk("rule_entry: %u\n", rule_entry);

					if (rule_entry) {
						//bpf_trace_printk("Entered rule: %u\n", rule_entry);
                        //bpf_trace_printk("IP packet:\n");
						//bpf_trace_printk("Source IP: %u, Destination IP: %u\n", src_ip, dest_ip);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", src_port, dest_port);
                        //bpf_trace_printk("In rule:\n");
                        //bpf_trace_printk("Source IP: %u, Destination IP: %u\n", rule_entry->source, rule_entry->destination);
                        bpf_trace_printk("Source port: %u, to destination port: %u\n", rule_entry->srcport, rule_entry->destport);

						if ((rule_entry->source == 0||src_ip == rule_entry->source) && (dest_ip == rule_entry->destination||rule_entry->destination == 0) && (rule_entry->srcport == 0||src_port == rule_entry->srcport) && (rule_entry->destport == 0 || dest_port == rule_entry->destport)){
							bpf_trace_printk("Processed source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
							if (rule_entry->action == 1) {
								bpf_trace_printk("Blocked with rule: %u, TCP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
								bpf_trace_printk("Passed with rule: %u, TCP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_PASS;
							}
						}else{
                            if (i < 2){
                                bpf_trace_printk("Checked rule:%u. Checking next rule: %u\n", i ,i+1); 
                            } else {
                                bpf_trace_printk("Checked rule:%u. End of rule for TCP protocol", i); 
                            }
							
						}
					}
				} else if (i == 2){
                    //bpf_trace_printk("No matching rule for src and dest. Passed TCP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;
                }
			}

		} else if (protocol_number == IPPROTO_UDP) {
			//bpf_trace_printk("IPPROTO_UDP");
            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;
			u32 dest_ip = iph->daddr;

            // Extract source and destination ports
            void *transport_header = data + nh_off + sizeof(struct iphdr);
            if (transport_header + sizeof(struct tcphdr) > data_end) {
                return rc;
            }

            struct tcphdr *tcph = transport_header;
            u16 src_port = ntohs(tcph->source);
            u16 dest_port = ntohs(tcph->dest);

			// Declare rule_entry outside the if block
            struct rule *rule_entry;

            // Iterate over all rules for the specific protocol
            struct rulekey rule_key = {.index = protocol_number};
            int *value;

            // Iterate through rules
            for (int i = 0; i < 3; i++) {
                rule_key.index = i;
                value = rule_keys.lookup(&rule_key);
                if (value && *value == protocol_number) {
                    // Found a matching value in the hash
                    //bpf_trace_printk("Value found in rule_keys for index %d: %d\n", i, *value);

                    // Look up the rule in the rule_map
                    rule_entry = rule_map.lookup(&rule_key);
                    //bpf_trace_printk("rule_entry: %u\n", rule_entry);

					if (rule_entry) {
						//bpf_trace_printk("Entered rule: %u\n", rule_entry);
                        //bpf_trace_printk("IP packet:\n");
						//bpf_trace_printk("Source IP: %u, Destination IP: %u\n", src_ip, dest_ip);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", src_port, dest_port);
                        //bpf_trace_printk("In rule:\n");
                        //bpf_trace_printk("Source IP: %u, Destination IP: %u\n", rule_entry->source, rule_entry->destination);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", rule_entry->srcport, rule_entry->destport);
                        
                        if ((rule_entry->source == 0||src_ip == rule_entry->source) && (dest_ip == rule_entry->destination||rule_entry->destination == 0) && (rule_entry->srcport == 0||src_port == rule_entry->srcport) && (rule_entry->destport == 0 || dest_port == rule_entry->destport)){
							//bpf_trace_printk("Processed source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
							if (rule_entry->action == 1) {
								//bpf_trace_printk("Blocked with rule: %u, UDP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
								//bpf_trace_printk("Passed with rule: %u, UDP packet from source IP: %u, to destination IP: %u\n", rule_entry, src_ip, dest_ip);
								return XDP_PASS;
							}
						}else{
                            if (i < 2){
                                //bpf_trace_printk("Checked rule:%u. Checking next rule: %u\n", i ,i+1); 
                            } else {
                                //bpf_trace_printk("Checked rule:%u. End of rule for UDP protocol", i); 
                            }
							
						}
					}
				} else if (i == 2){
                    //bpf_trace_printk("No matching rule for src and dest. Passed UDP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;
                }
			}
		} else {
            //bpf_trace_printk("IP Packet with diffrent protocol than ICMP,TCP and UDP passed");
            rc = XDP_PASS;
        }
    } else if (h_proto == htons(ETH_P_IPV6)){
		//bpf_trace_printk("IPv6");
	} else if (h_proto == htons(ETH_P_ARP)){
		//bpf_trace_printk("ARP");
	} else if (h_proto == htons(ETH_P_RARP)){
		//bpf_trace_printk("Reverse ARP");
	}


    //bpf_trace_printk("Packet processed returned rc");
    return rc;
}
`
func usage() {
	fmt.Printf("Usage: %v <ifdev>\n", os.Args[0])
	fmt.Printf("e.g.: %v eth0\n", os.Args[0])
	os.Exit(1)
}

var ruleMap *bcc.Table
var ruleKeys *bcc.Table

func main() {
	if len(os.Args) != 2 {
		usage()
	}

	device := os.Args[1]

	// Read the BPF map file descriptor from a file or any communication channel
	mapFD := // Read the map file descriptor

	// Create a BPF Table from the map file descriptor
	ruleMap := bcc.NewTable(mapFD, nil)

	// ... (Rest of your second program logic)

	// Example: Attach BPF Program to Kprobe (replace with your actual logic)
	fn, err := module.Load("xdp_prog1", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Blocking packets from specific IPv4 addresses.\n")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	select {
	case <-sig:
		fmt.Println("Exiting...")
	}
}