//map_manager_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <bpf/bpf.h>

struct rule {
    char    name[64];
    int32_t action;
    int32_t protocol;
    uint32_t source_ip;
    uint32_t dest_ip;
    int16_t srcport;
    int16_t destport;
};

struct bpf_object *obj;

void cleanup_and_exit(int sig) {
    fprintf(stderr, "Received signal %d. Cleaning maps up and shutting down...\n", sig);

    if (obj) {
        bpf_object__close(obj);
    }

    exit(0);
}

int read_config(const char *filename, struct rule *my_rule) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening configuration file");
        return 1;
    }

    // Use an array to store IP address parts
    uint32_t temp_ip[4];

    if (fscanf(file, "name=%63s\n", my_rule->name) != 1 ||
        fscanf(file, "action=%d\n", &my_rule->action) != 1 ||
        fscanf(file, "protocol=%d\n", &my_rule->protocol) != 1 ||
        fscanf(file, "source_ip=%u.%u.%u.%u\n", &temp_ip[0], &temp_ip[1], &temp_ip[2], &temp_ip[3]) != 4 ||
        fscanf(file, "dest_ip=%u.%u.%u.%u\n", &temp_ip[0], &temp_ip[1], &temp_ip[2], &temp_ip[3]) != 4 ||
        fscanf(file, "srcport=%hd\n", &my_rule->srcport) != 1 ||
        fscanf(file, "destport=%hd\n", &my_rule->destport) != 1) {
        fprintf(stderr, "Error reading configuration file\n");
        fclose(file);
        return 1;
    }

    // Construct the IP addresses from the parts
    my_rule->source_ip = (temp_ip[0] << 24) | (temp_ip[1] << 16) | (temp_ip[2] << 8) | temp_ip[3];
    fscanf(file, "dest_ip=%u.%u.%u.%u\n", &temp_ip[0], &temp_ip[1], &temp_ip[2], &temp_ip[3]);
    my_rule->dest_ip = (temp_ip[0] << 24) | (temp_ip[1] << 16) | (temp_ip[2] << 8) | temp_ip[3];

    fclose(file);
    return 0;
}

int main(void) {
    signal(SIGINT, cleanup_and_exit);

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

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF map created and loaded successfully\n");
    printf("File Descriptor of BPF map: %d\n", bpf_map__fd(map));

    int key = 1;
    struct rule my_rule;
    if (read_config("rules.conf", &my_rule) != 0) {
        bpf_object__close(obj);
        return 1;
    }

    if (bpf_map_update_elem(bpf_map__fd(map), &key, &my_rule, BPF_ANY) != 0) {
        perror("Error inserting value into BPF map");
        bpf_object__close(obj);
        return 1;
    }

    printf("Value inserted into BPF map successfully\n");

    while (1) {
        sleep(1);
    }

    return 0;
}
