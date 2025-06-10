#ifndef MARGO_AUTH_MAC_SESSION_TYPES_H
#define MARGO_AUTH_MAC_SESSION_TYPES_H

#include <margo.h>
#include <mercury_macros.h>
#include <mercury_proc_string.h>
#include <stdlib.h>
#include <openssl/hmac.h>

typedef uint64_t session_id_t;
#define hg_proc_session_id_t hg_proc_uint64_t

typedef struct {
    uint64_t session_id;                 // uid_t cast into a larger int
    uint64_t seq_no;                     // sequence number
    unsigned char hmac[EVP_MAX_MD_SIZE]; // HMAC of the above two fields
} token_t;

static inline hg_return_t hg_proc_token_t(hg_proc_t proc, token_t *token)
{
    return hg_proc_memcpy(proc, token, sizeof(*token));
}

static inline void create_token(token_t* token,
                                session_id_t session_id,
                                uint64_t seq_no,
                                const char* key,
                                size_t key_len)
{
    token->session_id = session_id;
    token->seq_no = seq_no;
    unsigned int len = 0;
    HMAC(EVP_sha512(), key, key_len,
         (unsigned char *)token, sizeof(token->session_id) + sizeof(token->seq_no),
         token->hmac, &len);
    for(unsigned i = len; i < EVP_MAX_MD_SIZE; ++i)
        token->hmac[i] = 0;
}

static inline int check_token(token_t* token,
                              session_id_t session_id,
                              uint64_t seq_no,
                              const char* key,
                              size_t key_len)
{
    token_t expected = {0};
    create_token(&expected, session_id, seq_no, key, key_len);
    return memcmp(&expected, token, sizeof(expected)) == 0 ? 0 : -1;
}

MERCURY_GEN_PROC(auth_in_t, ((hg_string_t)(credential)))
MERCURY_GEN_PROC(auth_out_t, ((session_id_t)(session_id))((int32_t)(ret)))

MERCURY_GEN_PROC(hello_in_t, ((token_t)(token))((hg_string_t)(name)))
MERCURY_GEN_PROC(hello_out_t, ((int32_t)(ret)))

#endif
