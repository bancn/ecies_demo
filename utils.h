//
// Created by Bancn on 2022/8/10.
//

#ifndef ECIES_DEMO_UTILS_H
#define ECIES_DEMO_UTILS_H

#include <stdio.h>
#include <stdint.h>

#define ERROR_BREAK(msg, ret) \
    if (ret != 0) {           \
        printf(msg, ret);     \
        break;                \
    }                         \

void dump_buf(char *info, uint8_t* buf, size_t len);

typedef struct {
    uint8_t *buf;
    size_t size;
}BYTEOBJECT, *P_BYTEOBJECT;

#endif //ECIES_DEMO_UTILS_H
