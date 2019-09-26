#ifndef LIB_IBRS_LOADKEYS_H
#define LIB_IBRS_LOADKEYS_H
#define _GNU_SOURCE

#include "lib-ibrs-gm.h"

void load_keys(ibrs_public_params_t* public_params, ibrs_key_pair* keys, FILE* keys_stream);
void ibrs_keys_clear(ibrs_key_pair* keys);

#endif /* LIB_IBRS_LOADKEYS_H */