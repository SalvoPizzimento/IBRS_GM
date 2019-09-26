#ifndef LIB_IBRS_SIGN_H
#define LIB_IBRS_SIGN_H
#define _GNU_SOURCE

#include "lib-ibrs-gm.h"

void ibrs_sign(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg,
				int signer_idx, ibrs_key_pair* keys, ibrs_sig* sign, FILE* sign_stream);

#endif /* LIB_IBRS_SIGN_H */