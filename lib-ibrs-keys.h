/** @file lib-ibrs-keys.h
 *  @brief Prototipi delle chiavi del Group Member.
 *
 *  Contiene i prototipi per le chiavi,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#ifndef LIB_IBRS_LOADKEYS_H
#define LIB_IBRS_LOADKEYS_H
#define _GNU_SOURCE

#include "lib-ibrs-gm.h"

/** @brief Funzione per caricare una coppia di chiavi da un file.
 *  @param public_params parametri pubblici per lo schema crittografico
 *  @param keys struttura dove caricare le chiavi
 *  @param keys_stream file stream da cui caricare le chiavi
 */
void load_keys(ibrs_public_params_t* public_params, ibrs_key_pair* keys, FILE* keys_stream);

/** @brief Funzione per liberare la struttura chiavi.
 *  @param keys struttura da liberare
 */
void ibrs_keys_clear(ibrs_key_pair* keys);

#endif /* LIB_IBRS_LOADKEYS_H */