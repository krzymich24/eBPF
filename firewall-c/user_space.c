// bpf_map_example.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>

int main(void) {
    // Create BPF map
    struct bpf_object *obj;
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

    // Keep the program running
    sleep(10);

    // Clean up
    bpf_object__close(obj);

    return 0;

}



