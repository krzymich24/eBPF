// firewall_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>

#define MAX_ENTRIES 1024

struct bpf_object *obj;

// Signal handler to handle Ctrl+C
void cleanup_and_exit(int sig) {
    fprintf(stderr, "Received signal %d. Shutting down...\n", sig);

    if (obj) {
        bpf_object__close(obj);
    }

    exit(0);
}

int main(void) {
    // Install the signal handler
    signal(SIGINT, cleanup_and_exit);

    // Open the BPF object file
    struct bpf_object *obj;

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

    // Allocate memory for keys and values
    int keys[MAX_ENTRIES];
    long values[MAX_ENTRIES];

    // Iterate over all entries in the BPF map
    int key;
    int i = 0;

    // Initialize key to 0 before the loop
    key = 0;

    while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
        long value;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            keys[i] = key;
            values[i] = value;
            i++;
        }
    }

    // Print all key-value pairs
    printf("All values in the BPF map:\n");
    for (int j = 0; j < i; j++) {
        printf("Key: %d, Value: %ld\n", keys[j], values[j]);
    }

    // Keep the program running
    while (1) {
        sleep(1);
    }

    return 0;
}
