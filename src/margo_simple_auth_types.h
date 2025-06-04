#ifndef MARGO_SIMPLE_AUTH_TYPES_H
#define MARGO_SIMPLE_AUTH_TYPES_H

#include <margo.h>
#include <mercury_macros.h>
#include <mercury_proc_string.h>

MERCURY_GEN_PROC(auth_in_t, ((hg_string_t)(credential)))
MERCURY_GEN_PROC(auth_out_t, ((int32_t)(ret)))

#endif
