#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_ENTRIES 1024

int main(void) {
    // Open the BPF object file
    struct bpf_object *obj;

    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        return 1;
    }

    // Load the BPF object
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Find the map by name
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "my_map");
    if (!map) {
        fprintf(stderr, "Error finding BPF map by name: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Retrieve the file descriptor of the BPF map
    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "Error obtaining file descriptor for BPF map: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF map found successfully with FD: %d\n", map_fd);

    // Allocate memory for keys and values
    int keys[MAX_ENTRIES];
    long values[MAX_ENTRIES];

    // Declare 'next_key' before the loop
    int next_key;

    // Iterate over all entries in the BPF map
    int key;
    long value;
    int i = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
            keys[i] = key;
            values[i] = value;
            i++;
        }
        key = next_key;
    }

    // Print all key-value pairs
    printf("All values in the BPF map:\n");
    for (int j = 0; j < i; j++) {
        printf("Key: %d, Value: %ld\n", keys[j], values[j]);
    }

    // Keep the program running
    sleep(10);

    // Clean up
    bpf_object__close(obj);

    return 0;
}
