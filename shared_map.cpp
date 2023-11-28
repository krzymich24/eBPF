// shared_map.h
#ifndef SHARED_MAP_H
#define SHARED_MAP_H

#include <linux/bpf.h>

struct rule {
    int32_t action;
    int32_t protocol;
    int32_t source;
    int32_t destination;
    int16_t srcport;
    int16_t destport;
};

struct rulekey {
    int32_t index;
    int32_t protocol;
};

#endif // SHARED_MAP_H