#include <margo.h>
#include <munge.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <openssl/rand.h>
#include "common.h"
#include "uthash.h"
#include "margo_auth_complete_types.h"

typedef struct session_t {
    session_id_t     session_id;
    UT_hash_handle   hh; /* hash by session_id */
    uid_t            uid;
    uint64_t         seq_no;
    unsigned char    key[32];
    double           last_used;
    ABT_mutex_memory mtx;
} session_t;

typedef struct {
    margo_instance_id mid;
    char              self_addr[256];
    session_t*        sessions;
    ABT_mutex_memory  sessions_mtx;
} server_t;

static void authenticate(hg_handle_t handle);
DECLARE_MARGO_RPC_HANDLER(authenticate)

static void hello(hg_handle_t handle);
DECLARE_MARGO_RPC_HANDLER(hello)

static void close_session(hg_handle_t handle);
DECLARE_MARGO_RPC_HANDLER(close_session)

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

    // initialize margo
    server.mid = margo_init(protocol, MARGO_SERVER_MODE, 0, 0);
    ASSERT(server.mid != MARGO_INSTANCE_NULL,
           "Could not initialize margo with protocol %s\n", protocol);

    // get address of this server
    hg_return_t hret = margo_addr_self(server.mid, &address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_self failed with error: %s\n",
           HG_Error_to_string(hret));

    hg_size_t address_str_size = sizeof(server.self_addr);
    hret = margo_addr_to_string(server.mid, server.self_addr, &address_str_size, address);
    ASSERT(hret == HG_SUCCESS,
           "margo_addr_to_string failed with error: %s\n",
           HG_Error_to_string(hret));
    server.self_addr[sizeof(server.self_addr)-1] = '\0';

    margo_addr_free(server.mid, address);

    // TODO: use margo_push_finalize_callback to clear the content of server.sessions

    // register RPCs
    hg_id_t id;
    id = MARGO_REGISTER(server.mid, "authenticate", auth_in_t, auth_out_t, authenticate);
    margo_register_data(server.mid, id, &server, NULL);
    id = MARGO_REGISTER(server.mid, "hello", hello_in_t, hello_out_t, hello);
    margo_register_data(server.mid, id, &server, NULL);
    id = MARGO_REGISTER(server.mid, "close", close_in_t, close_out_t, close_session);
    margo_register_data(server.mid, id, &server, NULL);

    printf("Server running at address %s\n", server.self_addr);

    // TODO: add a ULT that periodically prunes server.sessions
    // of sessions that haven't been active in a while

    // run progress loop
    margo_wait_for_finalize(server.mid);

    return 0;

finish:
    margo_addr_free(server.mid, address);
    margo_finalize(server.mid);
    return ret;
}

void authenticate(hg_handle_t handle)
{
    auth_in_t    in         = {0};
    auth_out_t   out        = {0};
    hg_return_t  hret       = HG_SUCCESS;
    int          ret        = 0;
    munge_err_t  err        = 0;
    session_t*   session    = NULL;
    char*        payload    = NULL;
    int          payload_len;

    margo_instance_id     mid  = margo_hg_handle_get_instance(handle);
    const struct hg_info* info = margo_get_info(handle);
    server_t* server           = margo_registered_data(mid, info->id);
    session                    = calloc(1, sizeof(*session));

    // get the input from the RPC
    hret = margo_get_input(handle, &in);
    ASSERT(hret == HG_SUCCESS,
            "Could not deserialize input arguments\n");

    // decode the credential part
    err = munge_decode(in.credential, NULL, (void**)&payload, &payload_len, &session->uid, NULL);
    ASSERT(err == 0, "Failed to decode credential\n");
    ASSERT((unsigned)payload_len > sizeof(session->session_id) + 1,
           "Invalid munge payload size found in credential\n");

    // the payload should contain key + server address,
    // the key is 32 bytes of binary data
    // the server address is a null-terminated ASCII string

    // get the key from the payload
    memcpy(session->key, payload, sizeof(session->key));

    // check that this server is the intended destination
    ASSERT(strncmp(server->self_addr, payload + sizeof(session->key), payload_len - sizeof(session->key)) == 0,
           "Replay attempt, not intended destination for this RPC!\n");

    // create a session ID for this new connection
    ret = RAND_bytes((unsigned char*)(&session->session_id), sizeof(session->session_id));
    ASSERT(ret == 1, "Error generating random session ID\n");
    ret = 0;
    out.session_id = session->session_id;

    // print out some information
    struct passwd *pws = getpwuid(session->uid);
    printf("Authenticated with uid=%d (%s)\n", session->uid, pws->pw_name);

    // initialize last_used field for the session
    session->last_used = ABT_get_wtime();

    // insert the new session in the sessions hash
    ABT_mutex_lock(ABT_MUTEX_MEMORY_GET_HANDLE(&server->sessions_mtx));
    HASH_ADD(hh, server->sessions, session_id, sizeof(session->session_id), session);
    ABT_mutex_unlock(ABT_MUTEX_MEMORY_GET_HANDLE(&server->sessions_mtx));
    session = NULL;

finish:
    free(session);
    free(payload);
    out.ret = ret;
    margo_respond(handle, &out);
    margo_free_input(handle, &in);
    margo_destroy(handle);
}
DEFINE_MARGO_RPC_HANDLER(authenticate)

void hello(hg_handle_t handle)
{
    hello_in_t   in      = {0};
    hello_out_t  out     = {0};
    hg_return_t  hret    = HG_SUCCESS;
    int          ret     = 0;
    session_t*   session = NULL;

    margo_instance_id     mid  = margo_hg_handle_get_instance(handle);
    const struct hg_info* info = margo_get_info(handle);
    server_t* server           = margo_registered_data(mid, info->id);

    // get the input of the RPC
    hret = margo_get_input(handle, &in);
    ASSERT(hret == HG_SUCCESS, "Could not deserialize input arguments\n");

    // find the corresponding session
    ABT_mutex_lock(ABT_MUTEX_MEMORY_GET_HANDLE(&server->sessions_mtx));
    HASH_FIND(hh, server->sessions, &in.token.session_id, sizeof(in.token.session_id), session);
    if(session) ABT_mutex_lock(ABT_MUTEX_MEMORY_GET_HANDLE(&session->mtx));
    ABT_mutex_unlock(ABT_MUTEX_MEMORY_GET_HANDLE(&server->sessions_mtx));

    // check validity of the session
    ASSERT(session != NULL, "Could not find session\n");
    ASSERT(in.token.seq_no == session->seq_no,
           "Unexpected sequence number for session\n");

    // TODO if there is a ULT that clears the sessions periodically,
    // we should make sure it doesn't remove a session that's in use here

    // check the token sent by the client against the session
    ret = check_token(&in.token, in.token.session_id, in.token.seq_no,
                      (const char*)session->key, sizeof(session->key));

    if(ret == 0) {
        session->last_used = ABT_get_wtime();
        session->seq_no += 1;
        printf("Hello %s (username %s)\n", in.name, getpwuid(session->uid)->pw_name);
    } else {
        printf("Unauthorized attempt to call the hello RPC\n");
    }

finish:
    // cleanup
    if(session) ABT_mutex_unlock(ABT_MUTEX_MEMORY_GET_HANDLE(&session->mtx));
    out.ret = ret;
    margo_respond(handle, &out);
    margo_free_input(handle, &in);
    margo_destroy(handle);
}
DEFINE_MARGO_RPC_HANDLER(hello)

void close_session(hg_handle_t handle)
{
    close_in_t   in      = {0};
    close_out_t  out     = {0};
    hg_return_t  hret    = HG_SUCCESS;
    int          ret     = 0;
    session_t*   session = NULL;

    margo_instance_id     mid  = margo_hg_handle_get_instance(handle);
    const struct hg_info* info = margo_get_info(handle);
    server_t* server           = margo_registered_data(mid, info->id);

    // get the input of the RPC
    hret = margo_get_input(handle, &in);
    ASSERT(hret == HG_SUCCESS, "Could not deserialize input arguments\n");

    // find the corresponding session
    ABT_mutex_lock(ABT_MUTEX_MEMORY_GET_HANDLE(&server->sessions_mtx));
    HASH_FIND(hh, server->sessions, &in.token.session_id, sizeof(in.token.session_id), session);
    if(!session) {
        fprintf(stderr, "Could not find session\n");
        ret = -1;
        goto unlock;
    }

    // check validity of the session
    if(in.token.seq_no != session->seq_no) {
        fprintf(stderr, "Unexpected sequence number for session\n");
        ret = -1;
        goto unlock;
    }

    // check the token sent by the client against the session
    ret = check_token(&in.token, in.token.session_id, in.token.seq_no,
                      (const char*)session->key, sizeof(session->key));
    if(ret != 0) {
        fprintf(stderr, "Unauthorized attempt to call the close RPC\n");
        goto unlock;
    }

    // remove the session from the hash
    HASH_DELETE(hh, server->sessions, session);
    free(session);
    printf("Successfully removed session\n");

unlock:
    ABT_mutex_unlock(ABT_MUTEX_MEMORY_GET_HANDLE(&server->sessions_mtx));

finish:
    // cleanup
    out.ret = ret;
    margo_respond(handle, &out);
    margo_free_input(handle, &in);
    margo_destroy(handle);
}
DEFINE_MARGO_RPC_HANDLER(close_session)

