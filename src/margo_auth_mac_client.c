#include <margo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <munge.h>
#include <openssl/rand.h>
#include "common.h"
#include "margo_auth_mac_types.h"

typedef struct {
    margo_instance_id mid;
    hg_id_t           auth_id;
    hg_id_t           hello_id;
    unsigned char     key[32];
    uint64_t          seq_no;
} client_t;

static int client_authenticate(client_t* client, hg_addr_t address);
static int client_hello(client_t* client, hg_addr_t address, const char* name);

int main(int argc, char** argv)
{
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <server-address>\n", argv[0]);
        exit(-1);
    }

    int         ret     = 0;
    hg_return_t hret    = HG_SUCCESS;
    hg_addr_t   address = HG_ADDR_NULL;

    client_t client = {0};

    const char* server = argv[1];
    char protocol[16] = {0};
    for(int i=0; i < 16 && server[i] && server[i] != ':'; ++i) protocol[i] = server[i];
    protocol[15] = '\0';

    client.mid = margo_init(protocol, MARGO_CLIENT_MODE, 0, 0);
    ASSERT(client.mid != MARGO_INSTANCE_NULL,
           "Could not initialize margo with protocol %s\n", protocol);

    client.auth_id  = MARGO_REGISTER(client.mid, "authenticate", auth_in_t, auth_out_t, NULL);
    client.hello_id = MARGO_REGISTER(client.mid, "hello", hello_in_t, hello_out_t, NULL);

    ret = RAND_bytes(client.key, sizeof(client.key));
    ASSERT(ret == 1,
           "Error generating random key\n");

    hret = margo_addr_lookup(client.mid, server, &address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_lookup failed with error: %s\n",
           HG_Error_to_string(hret));

    // try to send a "hello" without being authenticated
    ret = client_hello(&client, address, "Matthieu");
    ASSERT(ret == -1, "client_hello should have returned -1 (not authenticated), returned %d\n", ret);

    // authenticate
    ret = client_authenticate(&client, address);
    ASSERT(ret == 0, "client_authenticate failed\n");

    // send a "hello" after being authenticated
    ret = client_hello(&client, address, "Matthieu");
    ASSERT(ret == 0, "client_hello failed\n");

finish:
    margo_addr_free(client.mid, address);
    margo_finalize(client.mid);
    return ret;
}

static int client_authenticate(client_t* client, hg_addr_t address)
{
    int         ret    = 0;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t hret   = HG_SUCCESS;
    auth_in_t   in     = {0};
    auth_out_t  out    = {0};
    munge_err_t err    = EMUNGE_SUCCESS;

    hret = margo_create(client->mid, address, client->auth_id, &handle);
    ASSERT(hret == HG_SUCCESS,
            "margo_create failed with error: %s\n",
            HG_Error_to_string(hret));

    err = munge_encode(&in.credential, NULL, client->key, sizeof(client->key));
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

    ret = out.ret;

finish:
    free(in.credential);
    margo_free_output(handle, &out);
    margo_destroy(handle);
    return ret;
}

static int client_hello(client_t* client, hg_addr_t address, const char* name)
{
    int         ret    = 0;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t hret   = HG_SUCCESS;
    hello_in_t   in    = {0};
    hello_out_t  out   = {0};

    create_token(&in.token, getuid(), client->seq_no, (const char*)client->key, sizeof(client->key));
    in.name = (char*)name;

    hret = margo_create(client->mid, address, client->hello_id, &handle);
    ASSERT(hret == HG_SUCCESS,
            "margo_create failed with error: %s\n",
            HG_Error_to_string(hret));

    hret = margo_forward(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "margo_forward failed with error: %s\n",
           HG_Error_to_string(hret));

    hret = margo_get_output(handle, &out);
    ASSERT(hret == HG_SUCCESS,
           "margo_get_output failed with error: %s\n",
           HG_Error_to_string(hret));

    ret = out.ret;
    if(ret == 0) client->seq_no++;

finish:
    margo_free_output(handle, &out);
    margo_destroy(handle);
    return ret;
}
