//map_manager_user.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <termios.h>
#include <errno.h>  // Add this line for errno
#include <bpf/bpf.h>
#include <arpa/inet.h>

#define MAX_RULES 10

struct rule {
    char name[64];
    int32_t action;
    int32_t protocol;
    uint32_t source_ip;
    uint32_t dest_ip;
    uint16_t srcport;
    uint16_t destport;
    char srcport_str[16];  // String representation of srcport
    char destport_str[16]; // String representation of destport
    char srcip_str[16];  // String representation of srcport
    char destip_str[16]; // String representation of destport
};

struct bpf_object *obj;

//function clearing and closing bpf object when program is closing 
void cleanup_and_exit(int sig);

// Function to set terminal to non-blocking mode
void set_nonblock(int state);

// Function to clear rule map and read rules from file
void clean_map(void);

//Reading from .conf file 
int read_config(const char *filename, struct rule *rules, size_t *num_rules);

//main program responsible for creating, loading and managing map
int main(int argc, char *argv[]) {
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

    struct rule rules[MAX_RULES];
    size_t num_rules;

    // Read the configuration file name from the command line
    const char *config_filename = (argc > 1) ? argv[1] : "rules.conf";

    // Read rules from the specified configuration file
    clean_map();

    if (read_config(config_filename, rules, &num_rules) != 0) {
        bpf_object__close(obj);
        return 1;
    }

    // Insert the rules into the BPF map
    for (size_t i = 0; i < num_rules; i++) {
        if (bpf_map_update_elem(bpf_map__fd(map), &i, &rules[i], BPF_ANY) != 0) {
            perror("Error inserting value into BPF map");
            bpf_object__close(obj);
            return 1;
        }
    }

    printf("%zu values inserted into BPF map successfully\n", num_rules);

    // Exit the program after processing the rules
    cleanup_and_exit(0);
}

void clean_map() {
    struct bpf_map *map = bpf_map__next(NULL, obj);

    // Read existing keys from the map
    __u32 key;
    void *value;

    // Delete each existing entry
    for (int i = 0; bpf_map_get_next_key(bpf_map__fd(map), &key, &key) == 0; i++) {
        if (bpf_map_delete_elem(bpf_map__fd(map), &key) != 0) {
            // Ignore ENOENT (No such file or directory) error, as it may indicate that the entry doesn't exist
            if (errno != ENOENT) {
                perror("Error deleting entry from BPF map");
                bpf_object__close(obj);
                exit(1);
            }
        }
    }

}

int read_config(const char *filename, struct rule *rules, size_t *num_rules) {
    
     FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening configuration file");
        return 1;
    }

    // Use an array to store IP address parts
    uint32_t temp_ip[4];

    *num_rules = 0;

    while (*num_rules < MAX_RULES) {
        int result = fscanf(file, "name=%63s\n", rules[*num_rules].name);
        if (result == EOF) {
            // End of file reached
            break;
        } else if (result != 1) {
            // Error reading the name, skip the line
            fscanf(file, "%*[^\n]\n");
            continue;
        }

        // Skip lines starting with '#'
        if (rules[*num_rules].name[0] == '#') {
            fscanf(file, "%*[^\n]\n");
            continue;
        }

        // Continue reading other fields
        if (fscanf(file, "action=%d\n", &rules[*num_rules].action) != 1 ||
            fscanf(file, "protocol=%d\n", &rules[*num_rules].protocol) != 1 ||
            fscanf(file, "source_ip=%15s\n", rules[*num_rules].srcip_str) != 1 ||
            fscanf(file, "dest_ip=%15s\n", rules[*num_rules].destip_str) != 1 ||
            fscanf(file, "srcport=%15s\n", rules[*num_rules].srcport_str) != 1 ||
            fscanf(file, "destport=%15s\n", rules[*num_rules].destport_str) != 1) {
            
            // Error reading one of the fields, skip the rest of the line
            fscanf(file, "%*[^\n]\n");
            continue;
        }
        
        // Handle wildcard characters in source IP
        if (strcmp(rules[*num_rules].srcip_str, "*") == 0) {
            rules[*num_rules].source_ip = 0;  // Set to wildcard value
        } else {
            sscanf(rules[*num_rules].srcip_str, "%u.%u.%u.%u", &temp_ip[0], &temp_ip[1], &temp_ip[2], &temp_ip[3]);
            rules[*num_rules].source_ip = (temp_ip[0] << 24) | (temp_ip[1] << 16) | (temp_ip[2] << 8) | temp_ip[3];
        }

        // Handle wildcard characters in destination IP
        if (strcmp(rules[*num_rules].destip_str, "*") == 0) {
            rules[*num_rules].dest_ip = 0;  // Set to wildcard value
        } else {
            sscanf(rules[*num_rules].destip_str, "%u.%u.%u.%u", &temp_ip[0], &temp_ip[1], &temp_ip[2], &temp_ip[3]);
            rules[*num_rules].dest_ip = (temp_ip[0] << 24) | (temp_ip[1] << 16) | (temp_ip[2] << 8) | temp_ip[3];
        }

        // Check for wildcard character '*' and set port to 0 if found
        if (strcmp(rules[*num_rules].srcport_str, "*") == 0) {
            rules[*num_rules].srcport = 0;  // Set to wildcard value
        } else {
            rules[*num_rules].srcport = htons((uint16_t)atoi(rules[*num_rules].srcport_str));
        }

        if (strcmp(rules[*num_rules].destport_str, "*") == 0) {
            rules[*num_rules].destport = 0;  // Set to wildcard value
        } else {
            rules[*num_rules].destport = htons((uint16_t)atoi(rules[*num_rules].destport_str));
        }

        (*num_rules)++;
    }

    fclose(file);
    return 0;
}

void cleanup_and_exit(int sig) {
    fprintf(stderr, "Received signal %d. Cleaning maps up and shutting down...\n", sig);

    if (obj) {
        bpf_object__close(obj);
    }

    exit(0);
}

void set_nonblock(int state) {
    struct termios ttystate;

    // Get the terminal state
    tcgetattr(STDIN_FILENO, &ttystate);

    if (state == 0) {
        // Set to non-blocking mode
        ttystate.c_lflag &= ~ICANON;
    } else {
        // Set to blocking mode
        ttystate.c_lflag |= ICANON;
    }

    // Apply the new settings
    tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
}
