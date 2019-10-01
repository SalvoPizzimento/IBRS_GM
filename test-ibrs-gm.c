#include "lib-ibrs-helper.h"

#define prng_sec_level 96
#define default_sec_level 80

void setup_group(char* username, char* filename, char* groupname, int check){
    
    char* read_buffer;
    char* send_buffer;
    send_buffer = calloc(1024, sizeof(char));
    sprintf(send_buffer, "%s,%s", username, groupname);

    // INVIO USERNAME E GROUPNAME
    snd_data(socket_id, send_buffer, strlen(send_buffer));
	free(send_buffer);

    // CONFERMA DI AVVENUTA RICEZIONE
    read_buffer = calloc(1024, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);

    if(strncmp(read_buffer, "NULL", 4) == 0){
        printf("Username o Groupname invalido..\n");
    	free(read_buffer);
        exit(EXIT_FAILURE);
    }

    if(strncmp(read_buffer, "ACK", 3) != 0){
    	printf("Server non raggiungibile..\n");
    	free(read_buffer);
        exit(EXIT_FAILURE);
    }
    free(read_buffer);

    // INVIO LISTA UTENTI E USERNAME AL GA
    if(check == 1){
        
        FILE* list_file;
        char* file_buffer;
        long file_size;

        list_file = fopen(filename, "r");
        if(list_file == NULL){
        	printf("File lista utenti inesistente...\n");
        	exit(EXIT_FAILURE);
        }
        file_size = get_filesize(list_file);

        read_buffer = calloc(500, sizeof(char));
        sprintf(read_buffer, "%ld", file_size);
        snd_data(socket_id, read_buffer, 500);
        free(read_buffer);

        file_buffer = calloc(file_size, sizeof(char));
        if(fread(file_buffer, sizeof(char), file_size, list_file) != file_size){
            printf("problema nella read del file %s\n", filename);
            exit(EXIT_FAILURE);
        }
        snd_data(socket_id, file_buffer, strlen(file_buffer));
        fclose(list_file);
        free(file_buffer);
    }
    else{
        // INVIO GRANDEZZA FILE FITTIZIA
        snd_data(socket_id, "4", 1);
        // INVIO FILE IDS NULLO
    	snd_data(socket_id, "NULL", 4);
    }

    FILE *file_to_open;
    // RICEZIONE DATI PAIRING
    read_buffer = calloc(1024, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);
    
    if(strncmp(read_buffer, "NULL", 4) == 0){
        printf("Gruppo inesistente...\n");
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    else if(strncmp(read_buffer, "EXIST", 5) == 0){
        printf("Gruppo già esistente...\n");
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    else if(strncmp(read_buffer, "FAIL_AUTH", 9) == 0){
        printf("Autenicazione fallita...\n");
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    else if(strncmp(read_buffer, "EMPTY", 5) == 0){
        printf("File IDS non valido...\n");ù
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    
    file_to_open = fopen("pairing.txt", "w");
    fprintf(file_to_open, "%s", read_buffer);
    fclose(file_to_open);
    free(read_buffer);
    
    // RICEZIONE PARAMETRI
    read_buffer = calloc(1024, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);

    file_to_open = fopen("param.txt","w");
    fprintf(file_to_open, "%s", read_buffer);
    fclose(file_to_open);
    free(read_buffer);

    snd_data(socket_id, "ACK", 3);

    // RICEZIONE CHIAVI
    read_buffer = calloc(1024, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);
    
    file_to_open = fopen("keys.txt","w");
    fprintf(file_to_open, "%s", read_buffer);
    fclose(file_to_open);
    free(read_buffer);
}

// FUNZIONE DI COMUNICAZIONE CON IL CLOUD SERVER
void setup_CS(char* username, char* filename, char* groupname, int check){
    char* send_buffer;
    char* read_buffer;

    // INVIO USERNAME
    snd_data(socket_id, username, strlen(username));

    // RICEZIONE ACK
    read_buffer = calloc(1024, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);
    free(read_buffer);
    
    // INVIO GROUPNAME E FILENAME
    send_buffer = calloc(1024, sizeof(char));
    sprintf(send_buffer, "%s,%s", groupname, filename);
    snd_data(socket_id, send_buffer, strlen(send_buffer));
    free(send_buffer);

    read_buffer = calloc(50, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);

    if(strncmp(read_buffer, "NULL", 4) == 0){
        printf("Gruppo Inesistente...\n");
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    else if(strncmp(read_buffer, "FAIL_AUTH", 9) == 0){
        printf("Autenticazione fallita...\n");
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    else if(strncmp(read_buffer, "ACK", 3) != 0){
        printf("Cloud Server non risponde..\n");
        free(read_buffer);
        exit(EXIT_FAILURE);
    }
    else{
        free(read_buffer);
    }

    // MANDARE LA FIRMA DEL FILENAME
    srand(time(NULL));
    gmp_randstate_t prng;
    
    // Calibrating tools for timing
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    // Inizializing PRNG
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, prng_sec_level);

    ibrs_public_params_t public_params;
    FILE* pairing_stream, *param_stream, *keys_stream, *sign_stream;
    
    pairing_stream = fopen("pairing.txt", "r");
    param_stream = fopen("param.txt", "r");
    keys_stream = fopen("keys.txt", "r");
    sign_stream = fopen("sign.txt", "w+");

    load_params(&public_params, default_sec_level, pairing_stream, param_stream);
    
    int signer_idx = 0;
    array_ibrs ids;
    FILE* file_ids = fopen("i.txt", "r");

    char c;
    int num_lines = 1;

    for (c = getc(file_ids); c != EOF; c = getc(file_ids)){
        if (c == '\n') 
            num_lines += 1;
    }
    
    rewind(file_ids);
    
    if(file_ids!=NULL){
        char* line[num_lines];
        int j = 0;
        size_t len = 0;
       
        init_array_ibrs(&ids, num_lines);
        for(j = 0; j < num_lines; j++) {
            line[j] = NULL;
            len = 0;
            if(getline(&line[j], &len, file_ids) != -1){
                line[j][strcspn(line[j], "\r\n")] = 0;
                if(strcmp(line[j], username) == 0)
                    signer_idx = j;
                insert_id(&ids, line[j], j);
            }
        }
        fclose(file_ids);
    }
    
    // Loading keys
    ibrs_key_pair keys;
    load_keys(&public_params, &keys, keys_stream);
    
    // Signing
    ibrs_sig sign;
    ibrs_sign(&public_params, ids, (uint8_t *)filename, signer_idx, &keys, &sign, sign_stream);
       
    // INVIO FIRMA AL CLOUD SERVER
    FILE* list_file;
    char* file_buffer;
    long file_size;
    bool end = false;
    int offset = 0;

    list_file = fopen("sign.txt", "r");
    file_size = get_filesize(list_file);

    read_buffer = calloc(500, sizeof(char));
    sprintf(read_buffer, "%ld", file_size);
    printf("INVIO DELLA SIZE\n");
    snd_data(socket_id, read_buffer, 500);
    free(read_buffer);

    /*if(fread(file_buffer, sizeof(char), file_size, list_file) != file_size){
        printf("problema nella read del file sign.txt\n");
        free(file_buffer);
    	fclose(list_file);
        free(read_buffer);
        free_array(&ids);
	    ibrs_sign_clear(&sign);
	    ibrs_public_params_clear(&public_params);
	    gmp_randclear(prng);
        exit(EXIT_FAILURE);
    }*/

    while(!end){
        if(file_size < 1024)
            end = true;
        file_buffer = calloc(1024, sizeof(char));
        fseek(list_file, offset, SEEK_SET);
        if(fread(file_buffer, sizeof(char), 1024, list_file) > 1024){
            exit(EXIT_FAILURE);
        }
        if(!end){
            offset = offset + 1024;
            file_size = file_size - 1024;
        }
        snd_data(socket_id, file_buffer, strlen(file_buffer));
    }

    printf("INVIO DELLA FIRMA\n");

    free(file_buffer);
    fclose(list_file);

    read_buffer = calloc(1024, sizeof(char));
    rcv_data(socket_id, read_buffer, 1024);
    printf("RICEZIONE RISULTATO VERIFICA\n");

    if(strncmp(read_buffer, "FAIL", 4) == 0){
        printf("Firma errata...\n");
        free(read_buffer);
        free_array(&ids);
	    ibrs_sign_clear(&sign);
	    ibrs_public_params_clear(&public_params);
	    gmp_randclear(prng);
        exit(EXIT_FAILURE);
    }
    free(read_buffer);
/*
    key_buffer = calloc(2048, sizeof(char));
    offset = 0;
    for(int i=0; i<2; i++){
        read_buffer = calloc(1024, sizeof(char));
        rcv_data(socket_id, read_buffer, 1024);
        printf("READ_BUFFER: %s", read_buffer);
        offset += sprintf(key_buffer+offset, "%s", read_buffer);
        free(read_buffer);
    }
    printf("KEYPAIR: %s", key_buffer);
    free(key_buffer);*/

    if(check == 1){
    	snd_data(socket_id, "DOWNLOAD", 8);

	   	read_buffer = calloc(1024, sizeof(char));
	    rcv_data(socket_id, read_buffer, 1024);
        printf("READ_BUFFER: %s\n", read_buffer);

        char* command;
        command = calloc(500, sizeof(char));
        sprintf(command, "ubuntu@%s:/home/ubuntu/%s", getenv("CS"), filename);


	    if(strncmp(read_buffer, "DOWNLOAD", 8) == 0) {
            free(read_buffer);

            pid_t pid = fork();
            if(pid < 0){
                printf("errore nella fork");
            }
            else if(pid == 0){
                execl("/usr/bin/sudo", "/usr/bin/scp", "scp", "-i", "KeyPair.pem", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", command, ".", (char*)0);
            }
            wait(&pid);
            snd_data(socket_id, "ACK", 3);
	        printf("DOWNLOAD EFFETTUATO!\n");
            free(command);
	        free_array(&ids);
		    ibrs_sign_clear(&sign);
		    ibrs_public_params_clear(&public_params);
		    gmp_randclear(prng);
	        exit(EXIT_SUCCESS);
	    }
        else{
            free(command);
            free(read_buffer);
        }
    }
    else{
    	snd_data(socket_id, "UPLOAD", 6);

	    read_buffer = calloc(500, sizeof(char));
	    rcv_data(socket_id, read_buffer, 500);

	    if(strncmp(read_buffer, "READY", 5) == 0) {
            free(read_buffer);

	    	char* command;
	    	command = calloc(500, sizeof(char));
	    	sprintf(command, "ubuntu@%s:/home/ubuntu/", getenv("CS"));

	    	FILE* file_to_open;
	    	file_to_open = fopen(filename, "r");
	    	if(file_to_open == NULL){
	    		printf("FILE INESISTENTE...\n");
			    free_array(&ids);
			    ibrs_sign_clear(&sign);
			    ibrs_public_params_clear(&public_params);
			    gmp_randclear(prng);
		        exit(EXIT_FAILURE);
		    }
		    fclose(file_to_open);

            pid_t pid = fork();
	    	if(pid < 0){
				printf("errore nella fork");
			}
			else if(pid == 0){
				execl("/usr/bin/sudo", "/usr/bin/scp", "scp", "-i", "KeyPair.pem", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no", filename, command, (char*)0);
			}

            wait(&pid);
            snd_data(socket_id, "ACK", 3);
            
	        printf("UPLOAD EFFETTUATO!\n");
	    	free(command);
		    free_array(&ids);
		    ibrs_sign_clear(&sign);
		    ibrs_public_params_clear(&public_params);
		    gmp_randclear(prng);
	        exit(EXIT_SUCCESS);
	    }
        else
            free(read_buffer);
    }

    free_array(&ids);
    ibrs_sign_clear(&sign);
    ibrs_public_params_clear(&public_params);
    gmp_randclear(prng);
}

int main(int argc, char *argv[]) {

    char cmd[50];
    char username[50];
    char filename[50];
    char groupname[50];
    int socket_fd;

    printf("Scrivere \"1\" per comunicare con il Group_Admin, \nScrivere \"2\" per comunicare con il Cloud_Server.\n");
    if(fgets(cmd, sizeof(cmd), stdin) == NULL) {
        printf("problema nella fgets del cmd_0\n");
        exit(EXIT_FAILURE);
    }

    if(atoi(cmd) == 1){
        char* ip_ga;
        ip_ga = getenv("GA");

        socket_fd = connect_socket(ip_ga, 8080);
        socket_id = socket_fd;

        printf("\nScrivere \"1\" per creare un gruppo di condivisione, \nScrivere \"2\" per partecipare a un gruppo\n");
        if(fgets(cmd, sizeof(cmd), stdin) == NULL) {
            printf("problema nella fgets del cmd_1\n");
            exit(EXIT_FAILURE);
        }

        printf("\n Inserire il proprio username...\n");
        if(fgets(username, sizeof(username), stdin) == NULL) {
            printf("problema nella fgets dell'username\n");
            exit(EXIT_FAILURE);
        }
        username[strcspn(username, "\r\n")] = 0;

        if(atoi(cmd) == 1){
            printf("\n Inserire il nome del file contenente la lista di utenti...\n");
            if(fgets(filename, sizeof(filename), stdin) == NULL) {
                printf("problema nella fgets del filename\n");
                exit(EXIT_FAILURE);
            }
            filename[strcspn(filename, "\r\n")] = 0;
        
            printf("\n Inserire il nome del gruppo che si vuole creare...\n");
            if(fgets(groupname, sizeof(groupname), stdin) == NULL) {
                printf("problema nella fgets del groupname\n");
                exit(EXIT_FAILURE);
            }
            groupname[strcspn(groupname, "\r\n")] = 0;

            setup_group(username, filename, groupname, 1);
            printf("Gruppo creato e parametri ricevuti\n");
        }
        else if(atoi(cmd) == 2){
            printf("\n Inserire il nome del gruppo a cui si vuole accedere...\n");
            if(fgets(groupname, sizeof(groupname), stdin) == NULL) {
                printf("problema nella fgets del groupname\n");
                exit(EXIT_FAILURE);
            }
            groupname[strcspn(groupname, "\r\n")] = 0;
        
            setup_group(username, NULL, groupname, 0);
            printf("Parametri ricevuti\n");
        }
        else{
            printf("Comando errato..\n");
        }

        // close the socket 
        close(socket_fd);
    }
    else if(atoi(cmd) == 2){
        char* ip_cs;
        ip_cs = getenv("CS");

        socket_fd = connect_socket(ip_cs, 8888);
        socket_id = socket_fd;
        
        printf("\nScrivere \"1\" per effettuare un download, \nScrivere \"2\" per effettuare un upload.\n");
        if(fgets(cmd, sizeof(cmd), stdin) == NULL) {
            printf("problema nella fgets del cmd_2\n");
            exit(EXIT_FAILURE);
        }

        printf("\n Inserire il proprio username...\n");
        if(fgets(username, sizeof(username), stdin) == NULL) {
            printf("problema nella fgets dell'username\n");
            exit(EXIT_FAILURE);
        }
        username[strcspn(username, "\r\n")] = 0;
        
        if(atoi(cmd) == 1 || atoi(cmd) == 2){
            printf("Inserire il nome del file...\n");
            if(fgets(filename, sizeof(filename), stdin) == NULL) {
                printf("problema nella fgets del filename\n");
                exit(EXIT_FAILURE);
            }
            filename[strcspn(filename, "\r\n")] = 0;
        
            printf("\n Inserire il nome del gruppo a cui si vuole accedere...\n");
            if(fgets(groupname, sizeof(groupname), stdin) == NULL) {
                printf("problema nella fgets del groupname\n");
                exit(EXIT_FAILURE);
            }
            groupname[strcspn(groupname, "\r\n")] = 0;
            
            if(atoi(cmd) == 1)
                setup_CS(username, filename, groupname, 1);
            else
                setup_CS(username, filename, groupname, 0);
        }
        else{
            printf("Comando errato..\n");
        }

        // close the socket 
        close(socket_fd);
    }

    return 0;
}