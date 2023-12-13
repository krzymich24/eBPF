// map_manager_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>

// Define the rule structure
struct rule {
    char    name[64];
    int32_t action;
    int32_t protocol;
    int32_t source;
    int32_t destination;
    int16_t srcport;
    int16_t destport;
};

struct bpf_object *obj;

// Signal handler to handle Ctrl+C
void cleanup_and_exit(int sig) {
    fprintf(stderr, "Received signal %d. Cleaning maps up and shutting down...\n", sig);

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

    obj = bpf_object__open_file("map_manager_kern.o", NULL);

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
    int key = 1;
    struct rule my_rule;

    // Set values for the rule
    strncpy(my_rule.name, "my_rule_name", sizeof(my_rule.name));
    my_rule.action = 1;
    my_rule.protocol = 1;
    my_rule.source = 192 << 24 | 168 << 16 | 1 << 8 | 13;
    my_rule.destination = 192 << 24 | 168 << 16 | 1 << 8 | 2;
    my_rule.srcport = 80;
    my_rule.destport = 8080;

    if (bpf_map_update_elem(bpf_map__fd(map), &key, &my_rule, BPF_ANY) != 0) {
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
