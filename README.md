# eBPF
Master of Science Thesis

eBPF based firewall in golang and C

To work need:
golang 1.21
eBPF 
github.com/iovisor/gobpf/bcc


firewall.go is the main program

pipe.go is a program responible for taking logs from bpf_trace_pipe, translate them to human readable format and saving in another file
