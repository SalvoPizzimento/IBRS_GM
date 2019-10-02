/** @file lib-ibrs-verify.h
 *  @brief Prototipi della verifica del Group Member.
 *
 *  Contiene i prototipi per la verifica,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#ifndef LIB_IBRS_VER_H
#define LIB_IBRS_VER_H
#define _GNU_SOURCE

#include "lib-ibrs-gm.h"

/** @brief Funzione per verifica la correttezza della firma.
 *  @param public_params parametri pubblici per lo schema crittografico
 * 	@param l insieme delle identità che partecipano alla firma
 *  @param msg messaggio su cui verificare la firma
 *  @param sign firma da verificare
 *  @return true se la firma è valida, false altrimenti
 */
bool ibrs_sign_ver(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg, ibrs_sig* sign);

/** @brief Funzione per liberare la struttura firma.
 *  @param sig firma da liberare
 */
void ibrs_sign_clear(ibrs_sig* sig);

#endif /* LIB_IBRS_VER_H */