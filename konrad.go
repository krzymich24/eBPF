package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
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
								bpf_trace_printk("Blocked ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
								bpf_trace_printk("Passed ICMP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
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
						bpf_trace_printk("Entered rule: %u\n", rule_entry);
                        //bpf_trace_printk("IP packet:\n");
						//bpf_trace_printk("Source IP: %u, Destination IP: %u\n", src_ip, dest_ip);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", src_port, dest_port);
                        //bpf_trace_printk("In rule:\n");
                        //bpf_trace_printk("Source IP: %u, Destination IP: %u\n", rule_entry->source, rule_entry->destination);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", rule_entry->srcport, rule_entry->destport);

						if ((rule_entry->source == 0||src_ip == rule_entry->source) && (dest_ip == rule_entry->destination||rule_entry->destination == 0) && (rule_entry->srcport == 0||src_port == rule_entry->srcport) && (rule_entry->destport == 0 || dest_port == rule_entry->destport)){
							bpf_trace_printk("Processed source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
							if (rule_entry->action == 1) {
								bpf_trace_printk("Blocked TCP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
								bpf_trace_printk("Passed TCP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
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
                    bpf_trace_printk("No matching rule for src and dest. Passed TCP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
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
                    bpf_trace_printk("Value found in rule_keys for index %d: %d\n", i, *value);

                    // Look up the rule in the rule_map
                    rule_entry = rule_map.lookup(&rule_key);
                    //bpf_trace_printk("rule_entry: %u\n", rule_entry);

					if (rule_entry) {
						bpf_trace_printk("Entered rule: %u\n", rule_entry);
                        //bpf_trace_printk("IP packet:\n");
						//bpf_trace_printk("Source IP: %u, Destination IP: %u\n", src_ip, dest_ip);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", src_port, dest_port);
                        //bpf_trace_printk("In rule:\n");
                        //bpf_trace_printk("Source IP: %u, Destination IP: %u\n", rule_entry->source, rule_entry->destination);
                        //bpf_trace_printk("Source port: %u, to destination port: %u\n", rule_entry->srcport, rule_entry->destport);
                        
                        if ((rule_entry->source == 0||src_ip == rule_entry->source) && (dest_ip == rule_entry->destination||rule_entry->destination == 0) && (rule_entry->srcport == 0||src_port == rule_entry->srcport) && (rule_entry->destport == 0 || dest_port == rule_entry->destport)){
							//bpf_trace_printk("Processed source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
							if (rule_entry->action == 1) {
								bpf_trace_printk("Blocked UDP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
								return XDP_DROP;
							} else if (rule_entry->action == 0) {
								bpf_trace_printk("Passed UDP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
								return XDP_PASS;
							}
						}else{
                            if (i < 2){
                                bpf_trace_printk("Checked rule:%u. Checking next rule: %u\n", i ,i+1); 
                            } else {
                                bpf_trace_printk("Checked rule:%u. End of rule for UDP protocol", i); 
                            }
							
						}
					}
				} else if (i == 2){
                    bpf_trace_printk("No matching rule for src and dest. Passed UDP packet from source IP: %u, to destination IP: %u\n", src_ip, dest_ip);
                    return XDP_PASS;
                }
			}
		} else {
            bpf_trace_printk("IP Packet with diffrent protocol than ICMP,TCP and UDP passed");
            rc = XDP_PASS;
        }
    } else if (h_proto == htons(ETH_P_IPV6)){
		bpf_trace_printk("IPv6");
	} else if (h_proto == htons(ETH_P_ARP)){
		bpf_trace_printk("ARP");
	} else if (h_proto == htons(ETH_P_RARP)){
		bpf_trace_printk("Reverse ARP");
	}

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
	SrcPort     string `toml:"src_port"`
	Destination string `toml:"destination"`
	DestPort    string `toml:"dest_port"`
}

// Add the RuleKey struct definition
type RuleKey struct {
	Index int32
}

// Add a function to convert a RuleKey to bytes
func ruleKeyToBytes(key *RuleKey) []byte {
	size := int(unsafe.Sizeof(*key))
	data := (*[1 << 30]byte)(unsafe.Pointer(key))[:size:size]
	buf := make([]byte, size)
	copy(buf, data)
	return buf
}

// Add a function to update the rule_keys BPF table
func updateRuleKeys(index int32) error {
	key := &RuleKey{Index: index}
	bytes := ruleKeyToBytes(key)
	return ruleKeys.Set(bytes, []byte{})
}

// Add a function to retrieve all rule keys
func getAllRuleKeys() ([]*RuleKey, error) {
	var keys []*RuleKey
	iter := ruleKeys.Iter()
	for iter.Next() {
		keyBytes := iter.Key()
		var ruleKey RuleKey
		copy((*[1 << 30]byte)(unsafe.Pointer(&ruleKey))[:], keyBytes)
		keys = append(keys, &ruleKey)
	}
	return keys, nil
}


// convertIPToUint32 converts an IP address string to uint32
func convertIPToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("Invalid IP address: %s", ipStr)
	}
	ipBytes := ip.To4()
	if ipBytes == nil {
		return 0, fmt.Errorf("Invalid IPv4 address: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(ipBytes), nil
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
    var srcIP uint32
    if entry.Source != "*" {
        srcIPUint, err := convertIPToUint32(entry.Source)
        if err != nil {
            return nil, fmt.Errorf("Error converting Source IP to uint32: %v", err)
        }
        srcIP = srcIPUint
    }

    // Convert Destination IP address to uint32
    var destIP uint32
    if entry.Destination != "*" {
        destIPUint, err := convertIPToUint32(entry.Destination)
        if err != nil {
            return nil, fmt.Errorf("Error converting Destination IP to uint32: %v", err)
        }
        destIP = destIPUint
    }

    // Convert Source port to uint16
    var srcPort uint16
    if entry.SrcPort != "*" {
        srcPortUint, err := strconv.ParseUint(entry.SrcPort, 10, 16)
        if err != nil {
            return nil, fmt.Errorf("Error converting Source Port to uint16: %v", err)
        }
        srcPort = uint16(srcPortUint)
    }

    // Convert Destination port to uint16
    var destPort uint16
    if entry.DestPort != "*" {
        destPortUint, err := strconv.ParseUint(entry.DestPort, 10, 16)
        if err != nil {
            return nil, fmt.Errorf("Error converting Destination Port to uint16: %v", err)
        }
        destPort = uint16(destPortUint)
    }

	data := (*[1<<30]byte)(unsafe.Pointer(entry))[:size:size]
	copy(buf, data)

	binary.LittleEndian.PutUint32(buf[8:12], srcIP)          // Source IP offset in the struct
    binary.LittleEndian.PutUint32(buf[12:16], destIP)        // Destination IP offset in the struct
	binary.LittleEndian.PutUint16(buf[16:18], srcPort)   // Source port offset in the struct
    binary.LittleEndian.PutUint16(buf[18:20], destPort)

	return buf, nil
}



// updateBPFMapFromToml updates the BPF map with rules from a TOML file.
func updateBPFMapFromToml(filename string, ruleMap *bcc.Table, ruleKeys *bcc.Table) error {
	// Clear existing entries in ruleMap and ruleKeys
    ruleMap.DeleteAll()
    ruleKeys.DeleteAll()
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

	// Iterate through the rules and update the BPF maps
	for index, rule := range rulesConfig.Rules {
		key := convertIntToBytes(int32(index))
		protocolKey := convertIntToBytes(rule.Protocol)

		ruleMapEntry := &Rule{
			Action:      rule.Action,
			Protocol:    rule.Protocol,
			Source:      rule.Source,
			SrcPort:     rule.SrcPort,
			Destination: rule.Destination,
			DestPort:    rule.DestPort,
		}

		updatedRuleEntryBytes, err := ruleEntryToBytes(ruleMapEntry)
		if err != nil {
			return fmt.Errorf("Error converting updated rule entry to bytes: %v", err)
		}

		err = ruleMap.Set(key, updatedRuleEntryBytes)
		if err != nil {
			return fmt.Errorf("Error inserting updated entry into BPF map: %v", err)
		}

		err = ruleKeys.Set(key, protocolKey)
		if err != nil {
			return fmt.Errorf("Error inserting key into ruleKeys map: %v", err)
		}

		fmt.Printf("Rule %d processed successfully. Key: %v, Entry: %v\n", index, key, updatedRuleEntryBytes)
	}

	fmt.Println("Finished processing rules from TOML file.")

	return nil
}

func waitForUpdateSignal() {
    for {
        fmt.Println("Press Enter to update rules from TOML...")
        _, err := fmt.Scanln()
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading user input: %v\n", err)
            close(updateSignal)
            return
        }
        updateSignal <- struct{}{}
    }
}

var updateSignal chan struct{} // Channel to signal map update

func usage() {
    fmt.Printf("Usage: %v <ifdev> <tomlfile>\n", os.Args[0])
    fmt.Printf("e.g.: %v eth0 config.toml\n", os.Args[0])
    os.Exit(1)
}

var module *bcc.Module

// BPF_TABLE is used to declare the rule_map BPF array
var rule_map *bcc.Table

// BPF_TABLE is used to declare the rule_map BPF array
var ruleKeys *bcc.Table

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

	// BPF_TABLE is used to declare the rule_map BPF array
	ruleKeys = bcc.NewTable(module.TableId("rule_keys"), module)

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

	err = updateBPFMapFromToml(tomlFile, rule_map, ruleKeys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update BPF map from TOML: %v\n", err)
		os.Exit(1)
	}

	defer func() {
        if err := module.RemoveXDP(device); err != nil {
            fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
        }

        // Delete BPF maps
        rule_map.DeleteAll()
        ruleKeys.DeleteAll()
    }()

	fmt.Printf("Blocking packets from specific IPv4 addresses. Use %v to update rules from TOML.\n", tomlFile)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	updateSignal = make(chan struct{})
    defer close(updateSignal)

    // Start the goroutine to wait for user input
    go waitForUpdateSignal()

	for {
        select {
        case <-updateSignal:
            // Handle map update here
            fmt.Println("Updating rules from TOML...")
            err := updateBPFMapFromToml(tomlFile, rule_map, ruleKeys)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Failed to update BPF map from TOML: %v\n", err)
            } else {
                fmt.Println("Rules updated successfully.")
            }

        case <-sig:
            elapsed := time.Since(start)
            seconds := elapsed.Seconds()
            fmt.Printf("\nIP packets blocked by %.2f seconds\n", seconds)
            return
        }
    }
}
