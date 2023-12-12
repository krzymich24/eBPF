//user_space.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>

struct bpf_object *obj;

// Signal handler to handle Ctrl+C
void cleanup_and_exit(int sig) {
    fprintf(stderr, "Received signal %d. Cleaning up...\n", sig);

    if (obj) {
        bpf_object__close(obj);
    }

    exit(0);
}

int main(void) {
    // Install the signal handler
    signal(SIGINT, cleanup_and_exit);

    // Create BPF map
    struct bpf_map *map;

    obj = bpf_object__open_file("bpf_program.o", NULL);

    if (!obj) {
        fprintf(stderr, "Error loading BPF object file\n");
        return 1;
    }

    map = bpf_map__next(NULL, obj);
    if (!map) {
        fprintf(stderr, "Error finding BPF map\n");
        bpf_object__close(obj);
        return 1;
    }

    // Update map attributes
    bpf_map__set_type(map, BPF_MAP_TYPE_HASH);
    bpf_map__set_key_size(map, sizeof(int));
    bpf_map__set_value_size(map, sizeof(long));
    bpf_map__set_max_entries(map, 1024);

    // Load BPF object and create the map
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF map created and loaded successfully\n");

    // Print the file descriptor of the map
    printf("File Descriptor of BPF map: %d\n", bpf_map__fd(map));

    // Insert a value into the map
    int key = 42;
    long value = 123;

    if (bpf_map_update_elem(bpf_map__fd(map), &key, &value, BPF_ANY) != 0) {
        perror("Error inserting value into BPF map");
        bpf_object__close(obj);
        return 1;
    }

    printf("Value inserted into BPF map successfully\n");

    // Keep the program running
    while (1) {
        sleep(1);
    }

    return 0;
}
