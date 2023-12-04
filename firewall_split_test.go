// read_maps.go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -lbcc
#include "shared_map.h"
*/
import "C"

const sharedMapSource string = `
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

var ruleMap *bcc.Table
var ruleKeys *bcc.Table

func main() {
	// Load the BPF module and create BPF tables
	module := bcc.NewModule(sharedMapSource, []string{"-w"})
	defer module.Close()

	// Load the BPF maps from the manager program
	ruleMap = bcc.NewTable(module.TableId("rule_map"), module)
	if ruleMap == nil {
		fmt.Fprintf(os.Stderr, "Failed to load rule_map\n")
		os.Exit(1)
	}

	ruleKeys = bcc.NewTable(module.TableId("rule_keys"), module)
	if ruleKeys == nil {
		fmt.Fprintf(os.Stderr, "Failed to load rule_keys\n")
		os.Exit(1)
	}

	// Set up a channel to receive signals
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	// Read and print entries from the BPF map
	fmt.Println("Reading entries from BPF map...")

	// Wait for signals
	select {
	case <-signalCh:
		fmt.Println("Received interrupt signal. Stopping the program.")
	}
}
