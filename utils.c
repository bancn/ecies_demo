//
// Created by Bancn on 2022/8/10.
//


#include "utils.h"

void dump_buf(char *info, uint8_t* buf, size_t len)
{
    printf("%s:%zu\r\n", info, len);

    for (int i = 0; i < len; ++i) {
        printf("%s%02x%s",
               i%16 == 0 ? "\r\n    " : " ",
               buf[i],
               i == len - 1 ? "\n" : "");
    }
}