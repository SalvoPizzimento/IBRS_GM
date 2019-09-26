#include "lib-ibrs-helper.h"

int connect_socket(char serv_addr[], int port){

	int socket_fd; 
    struct sockaddr_in servaddr; 
  
    // socket create and varification 
    socket_fd = socket(AF_INET, SOCK_STREAM, 0); 
    if (socket_fd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr));
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr(serv_addr); 
    servaddr.sin_port = htons(port);

    if (connect(socket_fd, (SA*)&servaddr, sizeof(servaddr)) != 0) { 
        printf("connection with the server failed...\n"); 
        exit(0);
    } 
    else
        printf("connected to the server..\n");

    socket_id = socket_fd;
    return socket_fd;
}