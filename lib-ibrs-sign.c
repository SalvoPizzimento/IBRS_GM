/** @file lib-ibrs-sign.c
 *  @brief Firma per il Group Member.
 *
 *  File contenente le funzioni per 
 *  gestire la firma dello schema IBRS.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#include "lib-ibrs-sign.h"

void ibrs_sign(ibrs_public_params_t* public_params, array_ibrs l, const uint8_t* msg,
				int signer_idx, ibrs_key_pair* keys, ibrs_sig* sign, FILE* sign_stream) {
	assert(public_params);
	assert(l.size>0);
	assert(signer_idx>=0);
	assert(keys);
	assert(msg);
	assert(sign);

	element_t r_s, u_i, u_s, el_h_s, pre_v, el_h_i, el_qid_i, rs_qids, mul, pre_sum, sum;
	
	uint8_t h_i[public_params->size_from_sec_level];
	uint8_t h_s[public_params->size_from_sec_level];
	uint8_t qid_i[public_params->size_from_sec_level];

	size_t length = l.size;
	size_t size_buffer = sizeof(char *)*SINGLE_ALLOC_SIZE;
	char* l_buf =  calloc(l.size, size_buffer);

	char buffer_u[512];
	char* buffer;
	char tmp[64];

	//INIT ELEMENTS ZR
	element_init_Zr(r_s, public_params->pairing);
	element_init_Zr(el_h_i, public_params->pairing);

	//INIT ELEMENTS G1
	element_init_G1(u_i, public_params->pairing);
	element_init_G1(el_qid_i, public_params->pairing);
	element_init_G1(mul, public_params->pairing);
	element_init_G1(pre_sum, public_params->pairing);
	element_init_G1(sum, public_params->pairing);

	element_random(r_s);

	//SUM ELEMENTS OF ARRAY_IBRS
	for(int i=0; i<length; i++) {
		snprintf(tmp, sizeof(tmp), "%s", l.array[i]);
		strncat(l_buf, tmp, sizeof(tmp));
	}
	
	//INIT u_i array of sign
	init_array_element_t_ibrs(&sign->u_i, length);

	for(int j=0; j<length; j++) {
		if(j!=signer_idx){

			//INIT RANDOM Ui
			element_random(u_i);
			
			//INIT and SET sign->u_i[j]			
			element_init_G1(sign->u_i.array[j], public_params->pairing);
			element_set(sign->u_i.array[j], u_i);
			
			//INIT (m||L||Ui)
			element_snprint(buffer_u, sizeof(buffer_u), u_i);

			if(asprintf(&buffer, "%s%s%s", msg,l_buf,buffer_u) != -1) {
				//INIT hi as H0(m||L||Ui)
				sha256_update(&(public_params->ctx), strlen(buffer), (const uint8_t* ) buffer);
				sha256_digest(&(public_params->ctx), public_params->size_from_sec_level, h_i);
				element_from_hash(el_h_i, h_i, public_params->size_from_sec_level);
			}
			else {
				printf("Errore nella funzione asprint!");
				return;
			}
			
			//INIT QIDi as H(IDi)
			sha256_update(&(public_params->ctx), strlen(l.array[j]), (const uint8_t* ) l.array[j]);
			sha256_digest(&(public_params->ctx), public_params->size_from_sec_level, qid_i);
			element_from_hash(el_qid_i, qid_i, public_params->size_from_sec_level);

			//INIT hi*QIDi
			element_mul_zn(mul, el_qid_i, el_h_i);

			//SUM of Ui+(hi*QIDi)
			element_add(pre_sum, u_i, mul);

			//SUM of all Ui+(hi*QIDi)
			element_add(sum, sum, pre_sum);
		}
	}
	//INIT r's*QIDs
	element_init_G1(rs_qids, public_params->pairing);
	element_mul_zn(rs_qids, keys->qid, r_s);

	//INIT Us as r's*QIDs-sum
	element_init_G1(u_s, public_params->pairing);
	element_sub(u_s, rs_qids, sum);

	//INIT and SET sign->u_i[signer_idx]
	element_init_G1(sign->u_i.array[signer_idx], public_params->pairing);
	element_set(sign->u_i.array[signer_idx], u_s);

	//INIT (m||L||Us)
	element_snprint(buffer_u, sizeof(buffer_u), u_s);

	if(asprintf(&buffer, "%s%s%s", msg, l_buf, buffer_u) != -1) {
		//INIT hs as H0(m||L||Us)
		sha256_update(&(public_params->ctx), strlen(buffer), (const uint8_t* ) buffer);
		sha256_digest(&(public_params->ctx), public_params->size_from_sec_level, h_s);
	}
	else {
		printf("Errore nella funzione asprint!");
		return;
	}

	//CAST hs as an element of Zr
	element_init_Zr(el_h_s, public_params->pairing);
	element_from_hash(el_h_s, h_s, public_params->size_from_sec_level);

	//INIT pre_v as (hs+r's)
	element_init_Zr(pre_v, public_params->pairing);
	element_add(pre_v, el_h_s, r_s);
	
	//INIT V as pre_v*SIDs
	element_init_G1(sign->v, public_params->pairing);
	element_mul_zn(sign->v, keys->sid, pre_v);

	for(int k=0; k<length; k++) {
		element_fprintf(sign_stream, "%B\n", sign->u_i.array[k]);
	}
	element_fprintf(sign_stream, "%B\n", sign->v);

	//CLEARS of all element used
	element_clear(r_s);
	element_clear(u_i);
	element_clear(u_s);
	element_clear(el_h_s);
	element_clear(pre_v);
	element_clear(el_h_i);
	element_clear(el_qid_i);
	element_clear(rs_qids);
	element_clear(mul);
	element_clear(pre_sum);
	element_clear(sum);

	fclose(sign_stream);
	free(l_buf);

	printf("Firma effettuata.\n");
}