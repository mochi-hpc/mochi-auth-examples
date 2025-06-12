#include <margo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <munge.h>
#include <openssl/rand.h>
#include "common.h"
#include "margo_auth_complete_types.h"

typedef struct {
    margo_instance_id mid;
    hg_id_t           auth_id;
    hg_id_t           hello_id;
    hg_id_t           close_id;
} client_t;

typedef struct {
    const client_t* client;
    hg_addr_t       server_addr;
    session_id_t    session_id;
    uint64_t        seq_no;
    unsigned char   key[32];
} connection_t;

static int client_authenticate(const client_t* client, const char* address, connection_t* connection);
static int client_hello(connection_t* connection, const char* name);
static int client_close_session(connection_t* connection);

int main(int argc, char** argv)
{
    if(argc != 2) {
        fprintf(stderr, "Usage: %s <server-address>\n", argv[0]);
        exit(-1);
    }

    int          ret        = 0;
    client_t     client     = {0};
    connection_t connection = {0};
    const char* server      = argv[1];
    char protocol[16]       = {0};

    for(int i=0; i < 16 && server[i] && server[i] != ':'; ++i) protocol[i] = server[i];
    protocol[15] = '\0';

    // initialize margo
    client.mid = margo_init(protocol, MARGO_CLIENT_MODE, 0, 0);
    ASSERT(client.mid != MARGO_INSTANCE_NULL,
           "Could not initialize margo with protocol %s\n", protocol);

    // register RPCs
    client.auth_id  = MARGO_REGISTER(client.mid, "authenticate", auth_in_t, auth_out_t, NULL);
    client.hello_id = MARGO_REGISTER(client.mid, "hello", hello_in_t, hello_out_t, NULL);
    client.close_id = MARGO_REGISTER(client.mid, "close", close_in_t, close_out_t, NULL);

    // authenticate, initializing a connection_t instance
    ret = client_authenticate(&client, server, &connection);
    ASSERT(ret == 0, "Could not authenticate\n");

    // say hello multiple times using the connection_t instance
    ret = client_hello(&connection, "Matthieu");
    ASSERT(ret == 0, "client_hello(\"Matthieu\") failed\n");

    ret = client_hello(&connection, "Phil");
    ASSERT(ret == 0, "client_hello(\"Phil\") failed\n");

    ret = client_hello(&connection, "Rob");
    ASSERT(ret == 0, "client_hello(\"Rob\") failed\n");

    ret = client_close_session(&connection);
    ASSERT(ret == 0, "client_close_session failed\n");

finish:
    // cleanup
    margo_finalize(client.mid);
    return ret;
}

int client_authenticate(const client_t* client, const char* address, connection_t* connection)
{
    int         ret       = 0;
    hg_return_t hret      = HG_SUCCESS;
    hg_handle_t handle    = HG_HANDLE_NULL;
    hg_addr_t server_addr = HG_ADDR_NULL;
    munge_err_t err       = EMUNGE_SUCCESS;
    unsigned char key[32] = {0};
    char* payload         = NULL;
    size_t addr_len       = strlen(address);
    size_t payload_len    = sizeof(key) + addr_len;
    auth_in_t   in        = {0};
    auth_out_t  out       = {0};

    // create a random key for this connection
    ret = RAND_bytes(key, sizeof(key));
    ASSERT(ret == 1, "Error generating random key for new connection\n");

    // make the payload (client key + server address) for munge to encode
    payload = (char*)calloc(payload_len, 1);
    memcpy(payload, key, sizeof(key));
    mempcpy(payload + sizeof(key), address, addr_len);

    // have munge encode the payload
    err = munge_encode(&in.credential, NULL, payload, payload_len);
    ASSERT(err == EMUNGE_SUCCESS,
           "munge_encode failed: %s\n", munge_strerror(err));

    // lookup the server's address
    hret = margo_addr_lookup(client->mid, address, &server_addr);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_lookup(\"%s\") failed with error: %s\n",
           address, HG_Error_to_string(hret));

    // create the RPC handle
    hret = margo_create(client->mid, server_addr, client->auth_id, &handle);
    ASSERT(hret == HG_SUCCESS,
            "margo_create failed with error: %s\n",
            HG_Error_to_string(hret));

    // send the RPC
    hret = margo_forward(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "margo_forward failed with error: %s\n",
           HG_Error_to_string(hret));

    // get output from the RPC
    hret = margo_get_output(handle, &out);
    ASSERT(hret == HG_SUCCESS,
           "margo_get_output failed with error: %s\n",
           HG_Error_to_string(hret));

    ret = out.ret;

    // set the fields of the connection_t argument
    if(ret == 0) {
        connection->client     = client;
        connection->session_id = out.session_id;
        connection->seq_no     = 0;
        memcpy(connection->key, key, sizeof(key));
        margo_addr_dup(client->mid, server_addr, &connection->server_addr);
    }

finish:
    // cleanup
    free(payload);
    free(in.credential);
    margo_free_output(handle, &out);
    margo_destroy(handle);
    margo_addr_free(client->mid, server_addr);
    return ret;
}

int client_hello(connection_t* connection, const char* name)
{
    int         ret    = 0;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t hret   = HG_SUCCESS;
    hello_in_t   in    = {0};
    hello_out_t  out   = {0};

    // create the token for the RPC
    create_token(&in.token,
                 connection->session_id,
                 connection->seq_no,
                 (const char*)connection->key,
                 sizeof(connection->key));
    in.name = (char*)name;

    // create the RPC handle
    hret = margo_create(connection->client->mid,
                        connection->server_addr,
                        connection->client->hello_id,
                        &handle);
    ASSERT(hret == HG_SUCCESS,
            "margo_create failed with error: %s\n",
            HG_Error_to_string(hret));

    // send the RPC
    hret = margo_forward(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "margo_forward failed with error: %s\n",
           HG_Error_to_string(hret));

    // get the output of the RPC
    hret = margo_get_output(handle, &out);
    ASSERT(hret == HG_SUCCESS,
           "margo_get_output failed with error: %s\n",
           HG_Error_to_string(hret));

    ret = out.ret;

    // increment the sequence number
    if(ret == 0) connection->seq_no++;

finish:
    // cleanup
    margo_free_output(handle, &out);
    margo_destroy(handle);
    return ret;
}

int client_close_session(connection_t* connection)
{
    int         ret    = 0;
    hg_handle_t handle = HG_HANDLE_NULL;
    hg_return_t hret   = HG_SUCCESS;
    close_in_t   in    = {0};
    close_out_t  out   = {0};

    // create the token for the RPC
    create_token(&in.token,
                 connection->session_id,
                 connection->seq_no,
                 (const char*)connection->key,
                 sizeof(connection->key));

    // create the RPC handle
    hret = margo_create(connection->client->mid,
                        connection->server_addr,
                        connection->client->close_id,
                        &handle);
    ASSERT(hret == HG_SUCCESS,
            "margo_create failed with error: %s\n",
            HG_Error_to_string(hret));

    // send the RPC
    hret = margo_forward(handle, &in);
    ASSERT(hret == HG_SUCCESS,
           "margo_forward failed with error: %s\n",
           HG_Error_to_string(hret));

    // get the output of the RPC
    hret = margo_get_output(handle, &out);
    ASSERT(hret == HG_SUCCESS,
           "margo_get_output failed with error: %s\n",
           HG_Error_to_string(hret));

    ret = out.ret;

    margo_addr_free(connection->client->mid, connection->server_addr);
    memset(connection, 0, sizeof(*connection));

finish:
    // cleanup
    margo_free_output(handle, &out);
    margo_destroy(handle);
    return ret;
}
