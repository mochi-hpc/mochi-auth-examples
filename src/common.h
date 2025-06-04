#include <munge.h>
#include <stdlib.h>

#define ASSERT(cond, ...) do {        \
    if(!(cond)) {                     \
        fprintf(stderr, __VA_ARGS__); \
        ret = -1;                     \
        goto finish;                  \
    }                                 \
} while(0)

static inline munge_ctx_t create_munge_context() {
    munge_ctx_t ctx = munge_ctx_create();
    if(!ctx) return NULL;

    // Set an explicit MUNGE socket path
    munge_ctx_set(ctx, MUNGE_OPT_SOCKET, "/var/run/munge/munge.socket.2");
    return ctx;
}
