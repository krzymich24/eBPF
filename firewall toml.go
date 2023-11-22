package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"time"
	"unsafe"
	"net"

	"github.com/iovisor/gobpf/bcc"
	"github.com/pelletier/go-toml"
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
};

// Change from BPF_HASH to BPF_ARRAY
BPF_ARRAY(rule_map, struct rule, 3);

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

            bpf_trace_printk("Looking up Protocol: %d\n", protocol_number);
            struct rule *rule_entry = rule_map.lookup(&protocol_number);
            bpf_trace_printk("rule_entry: %u\n", rule_entry);
            if (rule_entry) {
				bpf_trace_printk("Entered rule: %u\n", rule_entry);
                if (src_ip == rule_entry->source && dest_ip == rule_entry->destination){
					bpf_trace_printk("Processed source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
					if (rule_entry->action == 1) {
                        bpf_trace_printk("Blocked ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                        return XDP_DROP;
                    } else {
                        bpf_trace_printk("Passed ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                        return XDP_PASS;
                    }
				}else{
					bpf_trace_printk("No matching src and dest. Passed ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;
				}
            }
        } else if (protocol_number == IPPROTO_TCP) {
			bpf_trace_printk("IPPROTO_TCP");
            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;

            bpf_trace_printk("Looking up Protocol: %d\n", protocol_number);
            struct rule *rule_entry = rule_map.lookup(&protocol_number);
            bpf_trace_printk("rule_entry: %u\n", rule_entry);
            if (rule_entry) {
                
                    if (rule_entry->action == 1) {
                        bpf_trace_printk("Blocked TCP packet from source IP: %u\n", src_ip);
                        rc = XDP_DROP;
                    } else {
                        bpf_trace_printk("Passed TCP packet from source IP: %u\n", src_ip);
                        return XDP_PASS;
                    }
            }
		} else if (protocol_number == IPPROTO_UDP) {
			bpf_trace_printk("IPPROTO_UDP");
            struct iphdr *iph = data + nh_off;
            u32 src_ip = iph->saddr;

            bpf_trace_printk("Looking up Protocol: %d\n", protocol_number);
            struct rule *rule_entry = rule_map.lookup(&protocol_number);
            bpf_trace_printk("rule_entry: %u\n", rule_entry);
            if (rule_entry) {
                
                    if (rule_entry->action == 1) {
                        bpf_trace_printk("Blocked TCP packet from source IP: %u\n", src_ip);
                        rc = XDP_DROP;
                    } else {
                        bpf_trace_printk("Passed TCP packet from source IP: %u\n", src_ip);
                        return XDP_PASS;
                    }
            }
		} else {
            bpf_trace_printk("Different Passed IP packet");
            rc = XDP_PASS;
        }
    } else if (h_proto == htons(ETH_P_IPV6)){
		bpf_trace_printk("IPv6");
	} else if (h_proto == htons(ETH_P_ARP)){
		bpf_trace_printk("ARP");
	} else if (h_proto == htons(ETH_P_RARP)){
		bpf_trace_printk("Reverse ARP");
	}


    bpf_trace_printk("Packet processed returned rc");
    return rc;
}
`

// Add the RulesConfig and Rule struct definitions at the top of your file

type RulesConfig struct {
    Rules []*Rule `toml:"rules"`
}

// Rule struct definition
type Rule struct {
    Action      int32  `toml:"action"`
    Protocol    int32  `toml:"protocol"`
    Source      string `toml:"source"`
    Destination string `toml:"destination"`
}

// convertIPToUint32 converts an IP address string to uint32
func convertIPToUint32(ipStr string) (uint32, error) {
    //fmt.Printf("Converting IP address %s to uint32\n", ipStr)

    ip := net.ParseIP(ipStr)
    if ip == nil {
        return 0, fmt.Errorf("Invalid IP address: %s", ipStr)
    }

    //fmt.Printf("Parsed IP: %v\n", ip)

    // Convert IPv4 address to uint32
    ipBytes := ip.To4()
    if ipBytes == nil {
        return 0, fmt.Errorf("Invalid IPv4 address: %s", ipStr)
    }

    //fmt.Printf("IPv4 bytes: %v\n", ipBytes)

    uint32Value := binary.LittleEndian.Uint32(ipBytes)

    fmt.Printf("Converted uint32 value: %v\n", uint32Value)

    return uint32Value, nil
}

// convertIntToBytes converts an integer to a byte slice
func convertIntToBytes(num int32) []byte {
    bytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(bytes, uint32(num))
    return bytes
}

// ruleEntryToBytes converts a rule entry to a byte slice
func ruleEntryToBytes(entry *Rule) ([]byte, error) {
    size := int(unsafe.Sizeof(*entry))
    buf := make([]byte, size)

    // Convert Source IP address to uint32
    srcIP, err := convertIPToUint32(entry.Source)
    if err != nil {
        return nil, fmt.Errorf("Error converting Source IP to uint32: %v", err)
    }

    // Convert Destination IP address to uint32
    destIP, err := convertIPToUint32(entry.Destination)
    if err != nil {
        return nil, fmt.Errorf("Error converting Destination IP to uint32: %v", err)
    }

    // Use unsafe.Pointer to convert the struct to a byte slice
    data := (*[1<<30]byte)(unsafe.Pointer(entry))[:size:size]

    // Copy the byte slice to the buffer
    copy(buf, data)

    // Update the Source and Destination fields in the buffer with the converted IP addresses
    binary.LittleEndian.PutUint32(buf[8:12], srcIP)       // Source IP offset in the struct
    binary.LittleEndian.PutUint32(buf[12:16], destIP)     // Destination IP offset in the struct

    return buf, nil
}


// updateBPFMapFromToml updates the BPF map with rules from a TOML file.
func updateBPFMapFromToml(filename string, ruleMap *bcc.Table) error {
    tomlContent, err := ioutil.ReadFile(filename)
    if err != nil {
        return fmt.Errorf("Error reading TOML file: %v", err)
    }

    var rulesConfig RulesConfig
    err = toml.Unmarshal(tomlContent, &rulesConfig)
    if err != nil {
        return fmt.Errorf("Error unmarshalling rules from TOML: %v", err)
    }

    fmt.Println("Processing rules from TOML file...")

    // Iterate through the rules and update the BPF map
    for index, rule := range rulesConfig.Rules {
        // Convert the index to a byte slice
        key := convertIntToBytes(int32(index)) // Convert index to int32

        // Update the rule entry with IP addresses directly
        ruleMapEntry := &Rule{
            Action:      rule.Action,
            Protocol:    rule.Protocol,
            Source:      rule.Source,
            Destination: rule.Destination,
        }

        // Convert the updated rule entry to a byte slice
        updatedRuleEntryBytes, err := ruleEntryToBytes(ruleMapEntry)
        if err != nil {
            return fmt.Errorf("Error converting updated rule entry to bytes: %v", err)
        }

        // Insert the updated entry
        err = ruleMap.Set(key, updatedRuleEntryBytes)
        if err != nil {
            return fmt.Errorf("Error inserting updated entry into BPF map: %v", err)
        }

        fmt.Printf("Rule %d processed successfully. Key: %v, Entry: %v\n", index, key, updatedRuleEntryBytes)
    }

    fmt.Println("Finished processing rules from TOML file.")

    return nil
}

// clearBPFMap clears all entries in the BPF map.
func clearBPFMap(ruleMap *bcc.Table) error {
    fmt.Println("Clearing BPF map...")

    // Iterate through the existing entries and delete them
    iter := ruleMap.Iter()
    for iter.Next() {
        key := iter.Key()
        err := ruleMap.Delete(key)
		if err != nil {
            fmt.Printf("Failed to delete entry from table: %v\n", err)
        }
        fmt.Printf("Deleted entry with key: %v\n", key)
    }

    fmt.Println("BPF map cleared successfully.")
    return nil
}

func usage() {
    fmt.Printf("Usage: %v <ifdev> <tomlfile>\n", os.Args[0])
    fmt.Printf("e.g.: %v eth0 config.toml\n", os.Args[0])
    os.Exit(1)
}

var module *bcc.Module

// BPF_TABLE is used to declare the rule_map BPF array
var rule_map *bcc.Table

func main() {
	start := time.Now()
	var device, tomlFile string

	if len(os.Args) != 3 {
		usage()
	}

	device = os.Args[1]
	tomlFile = os.Args[2]

	ret := "XDP_PASS"
	ctxtype := "xdp_md"

	module := bcc.NewModule(source, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
	})

	defer module.Close()

	// BPF_TABLE is used to declare the rule_map BPF array
	rule_map = bcc.NewTable(module.TableId("rule_map"), module)

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

	err = clearBPFMap(rule_map)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Failed to clear BPF map: %v\n", err)
        os.Exit(1)
    }

	err = updateBPFMapFromToml(tomlFile, rule_map)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update BPF map from TOML: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Printf("Blocking packets from specific IPv4 addresses. Use %v to update rules from TOML.\n", tomlFile)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	select {
	case <-sig:
		elapsed := time.Since(start)
		seconds := elapsed.Seconds()
		fmt.Printf("\nIP packets blocked by %.2f seconds\n", seconds)
	}
}
