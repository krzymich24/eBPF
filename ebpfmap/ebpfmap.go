// ebpfmap.go
package ebpfmap

import "github.com/iovisor/gobpf/bcc"

// CreateMap creates and returns the BPF maps from a given BPF module.
func CreateMap(module *bcc.Module) (*bcc.Table, *bcc.Table) {
    ruleMap := bcc.NewTable(module.TableId("rule_map"), module)
    ruleKeys := bcc.NewTable(module.TableId("rule_keys"), module)
    return ruleMap, ruleKeys
}