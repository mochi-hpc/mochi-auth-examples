#include <margo.h>
#include <munge.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include "common.h"
#include "margo_auth_mac_types.h"

typedef struct {
    margo_instance_id mid;
    struct {
        uint64_t      uid;
        uint64_t      seq_no;
        unsigned char key[32];
    } client; // in practice we would have a hash table of known clients
} server_t;

static void authenticate(hg_handle_t handle);
DECLARE_MARGO_RPC_HANDLER(authenticate)

static void hello(hg_handle_t handle);
DECLARE_MARGO_RPC_HANDLER(hello)

int main(int argc, char** argv)
{
    int ret = 0;

    if(argc != 2) {
        fprintf(stderr, "Usage: %s <protocol>\n", argv[0]);
        exit(-1);
    }

    hg_addr_t address    = HG_ADDR_NULL;
    const char* protocol = argv[1];

    server_t server = {0};

    server.mid = margo_init(protocol, MARGO_SERVER_MODE, 0, 0);
    ASSERT(server.mid != MARGO_INSTANCE_NULL,
           "Could not initialize margo with protocol %s\n", protocol);

    hg_id_t id;
    id = MARGO_REGISTER(server.mid, "authenticate", auth_in_t, auth_out_t, authenticate);
    margo_register_data(server.mid, id, &server, NULL);
    id = MARGO_REGISTER(server.mid, "hello", hello_in_t, hello_out_t, hello);
    margo_register_data(server.mid, id, &server, NULL);

    hg_return_t hret = margo_addr_self(server.mid, &address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_self failed with error: %s\n",
           HG_Error_to_string(hret));

    char      address_str[256];
    hg_size_t address_str_size = 256;
    hret = margo_addr_to_string(server.mid, address_str, &address_str_size, address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_to_string failed with error: %s\n",
           HG_Error_to_string(hret));
    address_str[255] = '\0';

    margo_addr_free(server.mid, address);

    printf("Server running at address %s\n", address_str);

    margo_wait_for_finalize(server.mid);

    return 0;

finish:
    margo_addr_free(server.mid, address);
    margo_finalize(server.mid);
    return ret;
}

void authenticate(hg_handle_t handle)
{
    auth_in_t   in   = {0};
    auth_out_t  out  = {0};
    hg_return_t hret = HG_SUCCESS;
    int         ret  = 0;
    munge_err_t err  = 0;
    void*       key  = NULL;
    int         key_len;
    uid_t       uid = -1;
    gid_t       gid = -1;

    margo_instance_id     mid  = margo_hg_handle_get_instance(handle);
    const struct hg_info* info = margo_get_info(handle);
    server_t* server           = margo_registered_data(mid, info->id);

    hret = margo_get_input(handle, &in);
    ASSERT(hret == HG_SUCCESS,
            "Could not deserialize input arguments\n");

    err = munge_decode(in.credential, NULL, &key, &key_len, &uid, &gid);
    ASSERT(err == 0,
           "Failed to decode credential\n");

    ASSERT(key_len == 32,
           "Key length is expected to be 32\n");

    struct passwd *pws = getpwuid(uid);
    printf("Authendicated with uid=%d (%s) and gid=%d\n", uid, pws->pw_name, gid);

    memcpy(server->client.key, key, 32);
    server->client.uid = (uint64_t)uid;
    server->client.seq_no = 0;

finish:
    free(key);
    out.ret = ret;
    margo_respond(handle, &out);
    margo_free_input(handle, &in);
    margo_destroy(handle);
}
DEFINE_MARGO_RPC_HANDLER(authenticate)

void hello(hg_handle_t handle)
{
    hello_in_t   in  = {0};
    hello_out_t  out = {0};
    hg_return_t hret = HG_SUCCESS;
    int         ret  = 0;

    margo_instance_id     mid  = margo_hg_handle_get_instance(handle);
    const struct hg_info* info = margo_get_info(handle);
    server_t* server           = margo_registered_data(mid, info->id);

    hret = margo_get_input(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "Could not deserialize input arguments\n");

    ret = check_token(&in.token, in.token.uid, in.token.seq_no,
                          (const char*)server->client.key, sizeof(server->client.key));

    if(ret == 0) {
        server->client.seq_no += 1;
        printf("Hello %s (username %s)\n", in.name, getpwuid(in.token.uid)->pw_name);
    } else {
        printf("Unauthorized attempt to call the hello RPC\n");
    }

finish:
    out.ret = ret;
    margo_respond(handle, &out);
    margo_free_input(handle, &in);
    margo_destroy(handle);
}
DEFINE_MARGO_RPC_HANDLER(hello)

