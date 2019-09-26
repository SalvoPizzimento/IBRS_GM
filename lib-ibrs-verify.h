#ifndef LIB_IBRS_VER_H
#define LIB_IBRS_VER_H
#define _GNU_SOURCE

#include "lib-ibrs-gm.h"

bool ibrs_sign_ver(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg, ibrs_sig* sign);
void ibrs_sign_clear(ibrs_sig* sig);

#endif /* LIB_IBRS_VER_H */