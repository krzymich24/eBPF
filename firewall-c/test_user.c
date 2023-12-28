// firewall_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <net/if.h>

#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

struct bpf_object *obj;
const char *interface; // Declare interface as a global variable

// Signal handler to handle Ctrl+C and termination signals
void cleanup_and_exit(int sig) {
    fprintf(stderr, "Received signal %d. Detaching BPF program and shutting down...\n", sig);

    // Detach BPF program before closing
    if (obj) {
        int ifindex = if_nametoindex(interface);
        int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "bpf_program1"));

        if (bpf_set_link_xdp_fd(ifindex, -1, 0) == -1) {
            fprintf(stderr, "Error detaching BPF program from interface %s: %s\n", interface, strerror(errno));
        }
        
        bpf_object__close(obj);
    }

    exit(0);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Set global interface variable
    interface = argv[1];

    // Install the signal handler for Ctrl+C and termination signals
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    // Open the BPF object file
    obj = bpf_object__open_file("firewall_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return 1;
    }

    // Retrieve the file descriptor of the existing BPF map (replace <your_map_name>)
    int map_fd = bpf_obj_get("/sys/fs/bpf/rule_map");

    if (map_fd < 0) {
        fprintf(stderr, "Error obtaining file descriptor for BPF map: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF map found successfully with FD: %d\n", map_fd);

    // Reuse the BPF map file descriptor
    if (bpf_map__reuse_fd(bpf_object__find_map_by_name(obj, "rule_map"), map_fd) != 0) {
        fprintf(stderr, "Error reusing BPF map file descriptor: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Load the BPF object
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Attach the BPF program to the XDP_TX hook on the specified interface
    int ifindex = if_nametoindex(interface);

    if (ifindex == 0) {
        fprintf(stderr, "Error getting interface index for %s: %s\n", interface, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "bpf_program1"));
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) == -1) {
        fprintf(stderr, "Error attaching BPF program to interface %s: %s\n", interface, strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF program attached to interface %s successfully\n", interface);

    // Keep the program running
    while (1) {
        sleep(1);
    }

    return 0;
}
