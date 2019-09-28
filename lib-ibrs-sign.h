/** @file lib-ibrs-sign.h
 *  @brief Prototipi della firma del Group Member.
 *
 *  Contiene i prototipi per la firma,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#ifndef LIB_IBRS_SIGN_H
#define LIB_IBRS_SIGN_H
#define _GNU_SOURCE

#include "lib-ibrs-gm.h"

/** @brief Funzione per effetturare una firma di un messaggio su un gruppo.
 *  @param public_params parametri pubblici per lo schema crittografico
 * 	@param l insieme delle identità che partecipano alla firma
 *  @param msg messaggio da firmare
 * 	@param signer_idx indice del firmatario rispetto alla lista di identità
 *  @param keys struttura con la coppia di chiavi del firmatario
 * 	@param sign struttura dove depositare la firma
 *  @param sign_stream file stream dove salvare la firma
 */
void ibrs_sign(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg,
				int signer_idx, ibrs_key_pair* keys, ibrs_sig* sign, FILE* sign_stream);

#endif /* LIB_IBRS_SIGN_H */