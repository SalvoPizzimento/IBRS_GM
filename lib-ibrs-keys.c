#include "lib-ibrs-keys.h"

void load_keys(ibrs_public_params_t* public_params, ibrs_key_pair* keys, FILE* keys_stream) {

	element_init_G1(keys->sid, public_params->pairing);
	element_init_G1(keys->qid, public_params->pairing);

	if(keys_stream!=NULL){
        char *line[2];
        size_t len = 0;
        
        for(int i = 0; i < 2; i++) {
			line[i] = NULL;
			len = 0;
			if(i==0){
				if(getline(&line[i], &len, keys_stream) != -1){
					element_set_str(keys->qid, line[i], 10);
				}
			}
			else{
				if(getline(&line[i], &len, keys_stream) != -1){
					element_set_str(keys->sid, line[i], 10);
				}
			}
        }

        fclose(keys_stream);
	}
    printf("Keys loaded.\n");
}

void ibrs_keys_clear(ibrs_key_pair* keys) {
	assert(keys);
	
	element_clear(keys->sid);
	element_clear(keys->qid);
}