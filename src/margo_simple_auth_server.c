#include <margo.h>
#include <munge.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include "common.h"
#include "margo_simple_auth_types.h"

static void authenticate(hg_handle_t handle);
DECLARE_MARGO_RPC_HANDLER(authenticate)

int main(int argc, char** argv)
{
    int ret = 0;

    if(argc != 2) {
        fprintf(stderr, "Usage: %s <protocol>\n", argv[0]);
        exit(-1);
    }

    hg_addr_t address    = HG_ADDR_NULL;
    const char* protocol = argv[1];

    margo_instance_id mid = margo_init(protocol, MARGO_SERVER_MODE, 0, 0);
    ASSERT(mid != MARGO_INSTANCE_NULL,
           "Could not initialize margo with protocol %s\n", protocol);

    MARGO_REGISTER(mid, "authenticate", auth_in_t, auth_out_t, authenticate);

    hg_return_t hret = margo_addr_self(mid, &address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_self failed with error: %s\n",
           HG_Error_to_string(hret));

    char      address_str[256];
    hg_size_t address_str_size = 256;
    hret = margo_addr_to_string(mid, address_str, &address_str_size, address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_to_string failed with error: %s\n",
           HG_Error_to_string(hret));
    address_str[255] = '\0';

    margo_addr_free(mid, address);

    printf("Server running at address %s\n", address_str);

    margo_wait_for_finalize(mid);

    return 0;

finish:
    margo_addr_free(mid, address);
    margo_finalize(mid);
    return ret;
}

void authenticate(hg_handle_t handle)
{
    auth_in_t   in   = {0};
    auth_out_t  out  = {0};
    hg_return_t hret = HG_SUCCESS;
    int         ret  = 0;
    munge_err_t err  = 0;

    munge_ctx_t ctx = create_munge_context();

    hret = margo_get_input(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "Could not deserialize input arguments\n");

    uid_t uid = -1;
    gid_t gid = -1;
    err = munge_decode(in.credential, ctx, NULL, NULL, &uid, &gid);
    ASSERT(err == 0,
           "Failed to decode credential\n");

    struct passwd *pws = getpwuid(uid);
    printf("Authendicated with uid=%d (%s) and gid=%d\n", uid, pws->pw_name, gid);

finish:
    munge_ctx_destroy(ctx);
    out.ret = ret;
    margo_respond(handle, &out);
    margo_free_input(handle, &in);
    margo_destroy(handle);
}
DEFINE_MARGO_RPC_HANDLER(authenticate)

