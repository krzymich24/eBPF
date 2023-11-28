//create_maps.go
package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil" // Add the import for "io/ioutil"
	"net"
	"os"
	"strconv"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"github.com/pelletier/go-toml"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "shared_map.h"
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
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

	binary.LittleEndian.PutUint32(buf[8:12], srcIP)       // Source IP offset in the struct
	binary.LittleEndian.PutUint32(buf[12:16], destIP)      // Destination IP offset in the struct
	binary.LittleEndian.PutUint16(buf[16:18], srcPort)     // Source port offset in the struct
	binary.LittleEndian.PutUint16(buf[18:20], destPort)    // Destination port offset in the struct

	return buf, nil
}

// updateBPFMapFromToml updates the BPF map with rules from a TOML file.
func updateBPFMapFromToml(filename string, ruleMap *bcc.Table, ruleKeys *bcc.Table) error {
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

func usage() {
	fmt.Printf("Usage: %v\n", os.Args[0])
	os.Exit(1)
}


var ruleMap *bcc.Table
var ruleKeys *bcc.Table

func main() {

	// Load the BPF module and create BPF tables
    module := bcc.NewModule(source, []string{
        "-w",
    })

	defer module.Close()

    // Load the BPF maps from the manager program
    ruleMap = bcc.NewTable(module.TableId("rule_map"), module)
    ruleKeys = bcc.NewTable(module.TableId("rule_keys"), module)

	// Expose the BPF map file descriptor
	ruleMapFD := module.TableId("rule_map")
	ruleKeysMapFD := module.TableId("rule_keys")

	file, err := os.Create("FDmaps")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create map_fds_file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	// Print the map IDs
	fmt.Printf("BPF maps created successfully. ruleMapFD: %d, ruleKeysMapFD: %d\n", ruleMapFD, ruleKeysMapFD)

	fmt.Fprintf(file, "ruleMapFD:%d\n,ruleKeysMapFD:%d", ruleMapFD, ruleKeysMapFD)

	fmt.Printf("BPF maps created successfully.\n")

	// Update BPF maps from a TOML file
	tomlFile := "config.toml"
	err = updateBPFMapFromToml(tomlFile, ruleMap, ruleKeys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update BPF map from TOML: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("BPF maps created and updated successfully from %v\n", tomlFile)

	// Infinite loop to keep the program running
	fmt.Println("Program is running. Press Ctrl+C to stop.")

	select {}
}