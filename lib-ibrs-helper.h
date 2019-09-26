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

#include "lib-timing.h"
#include "lib-ibrs-gm.h"
#include "lib-ibrs-params.h"
#include "lib-ibrs-keys.h"
#include "lib-ibrs-sign.h"
#include "lib-ibrs-verify.h"

#define SA struct sockaddr

int socket_id;
int connect_socket(char serv_addr[], int port);

#endif /* LIB_IBRS_HELPER_H */