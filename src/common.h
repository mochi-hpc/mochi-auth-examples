#include <stdlib.h>
#include <stdio.h>

#define ASSERT(cond, ...) do {        \
    if(!(cond)) {                     \
        fprintf(stderr, __VA_ARGS__); \
        ret = -1;                     \
        goto finish;                  \
    }                                 \
} while(0)
