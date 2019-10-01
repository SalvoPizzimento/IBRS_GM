/** @file lib-ibrs-helper.h
 *  @brief Prototipi delle funzioni per l'helper del Group Member.
 *
 *  Contiene i prototipi per l'helper,
 *  le macro, le costanti e tutte le variabili globali
 *  utili per il funzionamento.
 *
 *  @author Alessandro Midolo
 *  @author Salvatore Pizzimento
 */
#ifndef LIB_IBRS_HELPER_H
#define LIB_IBRS_HELPER_H
#define _GNU_SOURCE

#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <gmp.h>
#include <libgen.h>
#include <stdbool.h>
#include <assert.h>
#include <pbc/pbc.h>
#include <time.h> 
#include <sys/stat.h>
#include <sys/wait.h>

#include "lib-timing.h"
#include "lib-ibrs-gm.h"
#include "lib-ibrs-params.h"
#include "lib-ibrs-keys.h"
#include "lib-ibrs-sign.h"
#include "lib-ibrs-verify.h"

#define SA struct sockaddr
#define PORT_GA 8080
#define PORT_CS 8888

#define prng_sec_level 96
#define default_sec_level 80

int socket_id;
char* psw_cs;
char* ip_cs;

/** @brief Funzione per connettersi ad una socket tramite IP e PORTA.
 *  @param serv_addr[] indirizzo IP a cui connettersi
 *  @param port porta a cui connettersi
 *  @return descrittore della socket connessione socket creata
 */
int connect_socket(char serv_addr[], int port);

/** @brief Funzione per ricevere dati da una socket.
 *  @param socket_id socket da cui ricevere i dati
 *  @param read_buffer buffer dove depositare i dati ricevuti
 *  @param size numero di caratteri massimi da ricevere
 */
void rcv_data(int socket_id, char* read_buffer, int size);

/** @brief Funzione per inviare dati ad una socket.
 *  @param socket_id socket a cui mandare i dati
 *  @param buffer buffer di dati da inviare
 *  @param size numero di caratteri massimi da mandare
 */
void snd_data(int socket_id, char* buffer, int size);

#endif /* LIB_IBRS_HELPER_H */