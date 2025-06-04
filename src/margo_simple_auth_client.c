#include <margo.h>
#include <stdio.h>
#include <stdlib.h>
#include <munge.h>
#include "common.h"
#include "margo_simple_auth_types.h"

int main(int argc, char** argv)
{
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <server-address>\n", argv[0]);
        exit(-1);
    }

    int         ret       = 0;
    hg_return_t hret      = HG_SUCCESS;
    auth_in_t   in        = {0};
    auth_out_t  out       = {0};
    hg_addr_t   address   = HG_ADDR_NULL;
    hg_id_t authenticate  = 0;
    margo_instance_id mid = MARGO_INSTANCE_NULL;
    hg_handle_t handle    = HG_HANDLE_NULL;
    munge_err_t err       = EMUNGE_SUCCESS;

    const char* server = argv[1];
    char protocol[16] = {0};
    for(int i=0; i < 16 && server[i] && server[i] != ':'; ++i) protocol[i] = server[i];
    protocol[15] = '\0';

    mid = margo_init(protocol, MARGO_CLIENT_MODE, 0, 0);
    ASSERT(mid != MARGO_INSTANCE_NULL,
           "Could not initialize margo with protocol %s\n", protocol);

    authenticate = MARGO_REGISTER(mid, "authenticate", auth_in_t, auth_out_t, NULL);

    hret = margo_addr_lookup(mid, server, &address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_lookup failed with error: %s\n",
           HG_Error_to_string(hret));

    hret = margo_create(mid, address, authenticate, &handle);
    ASSERT(hret == HG_SUCCESS,
           "margo_create failed with error: %s\n",
           HG_Error_to_string(hret));

    err = munge_encode(&in.credential, NULL, NULL, 0);
    ASSERT(err == EMUNGE_SUCCESS,
           "munge_encode failed: %s\n", munge_strerror(err));

    hret = margo_forward(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "margo_forward failed with error: %s\n",
           HG_Error_to_string(hret));

    hret = margo_get_output(handle, &out);
    ASSERT(hret == HG_SUCCESS,
           "margo_get_output failed with error: %s\n",
           HG_Error_to_string(hret));

finish:
    free(in.credential);
    margo_free_output(handle, &out);
    margo_destroy(handle);
    margo_addr_free(mid, address);
    margo_finalize(mid);
    return ret;
}
