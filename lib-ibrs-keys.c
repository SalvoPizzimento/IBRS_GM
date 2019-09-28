/** @file lib-ibrs-keys.c
 *  @brief Chiavi per il Group Member.
 *
 *  File contenente le funzioni per 
 *  gestire le chiavi dello schema IBRS.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#include "lib-ibrs-keys.h"

void load_keys(ibrs_public_params_t* public_params, ibrs_key_pair* keys, FILE* keys_stream) {

	element_init_G1(keys->sid, public_params->pairing);
	element_init_G1(keys->qid, public_params->pairing);

	if(keys_stream!=NULL){
        char *line[2];
        size_t len = 0;
		
		line[0] = NULL;
		len = 0;
		if(getline(&line[0], &len, keys_stream) != -1){
			element_set_str(keys->qid, line[0], 10);
		}

		line[1] = NULL;
		len = 0;
		if(getline(&line[1], &len, keys_stream) != -1){
			element_set_str(keys->sid, line[1], 10);
		}
		
        fclose(keys_stream);
	}
    printf("Chiavi caricate.\n");
}

void ibrs_keys_clear(ibrs_key_pair* keys) {
	assert(keys);
	
	element_clear(keys->sid);
	element_clear(keys->qid);
}