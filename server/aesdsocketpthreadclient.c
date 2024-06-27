#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <assert.h>
#include "aesdsocketTypes.h"

#define D_BUFFER_SIZE 4096

extern server_state_t server_state;
extern void* get_in_addr(struct sockaddr *sa);

void* handle_client(void* client_socket) {
    int bytes_read;
    int total_bytes_read = 0;
    int fragment_number = 1;
    int fd_log = ((thread_node_t*)client_socket)->server->logger_fd;
    int sock = ((thread_node_t*)client_socket)->socket_fd;
    struct sockaddr_storage address;
    socklen_t sockaddrlen;
    char remoteIP[INET6_ADDRSTRLEN];
    char *token;
    printf("handle_client: argument client_socket: %p\n", client_socket);
    sockaddrlen = sizeof(struct sockaddr_storage);
    //free(client_socket);

    char *buffer = (char*)malloc(D_BUFFER_SIZE * sizeof(char));
    if (buffer == NULL)
    {
        pthread_exit(NULL);
    }

    if(0 != getpeername(sock, (struct sockaddr *)&address, &sockaddrlen))
    {
        syslog(LOG_DEBUG, "Unable to restore peer address, ignore for now!\n");
    }
    // Communicate with the client
    while(1) {
        memset(buffer + total_bytes_read, 0, (fragment_number * D_BUFFER_SIZE * sizeof(char)) - total_bytes_read);
        bytes_read = recv(sock, buffer + total_bytes_read, D_BUFFER_SIZE * sizeof(char), 0);
        if (bytes_read <= 0)
        {
            // Got error or connection closed by client
            if (bytes_read == 0)
            {
                // Connection closed
                syslog(LOG_DEBUG, "Closed connection from %s",
                        inet_ntop(address.ss_family, get_in_addr((struct sockaddr*) &address), remoteIP,
                                INET6_ADDRSTRLEN));
                printf("pollserver: socket %d hung up\n", sock);
            }
            else
            {
                perror("recv");
            }

//            close(sock);  // Bye!
            break;
        }
        else
        {
            char delimiter[] =
                { "\n" };
            char *ret;
            //printf("Total Byte received %d, last transaction received %d\n", total_bytes_read + bytes_read, bytes_read);
            token = memmem(buffer + total_bytes_read, (fragment_number * D_BUFFER_SIZE * sizeof(char)) - total_bytes_read, delimiter, sizeof(delimiter));
            printf("%s token\n", (token == NULL) ? ("Not found") : ("Found"));
            if (token != NULL)
            {
                int rbyte;
                total_bytes_read += bytes_read;
                // Lock mutex before accessing shared resources
                pthread_mutex_lock(&server_state.mutex);
                if (lseek(fd_log, 0, SEEK_END) == -1)
                {
                    perror("lseek");
                }
                //printf("Going to Write %d into fd_log\n", total_bytes_read);
                int wbyte = write(fd_log, buffer, total_bytes_read);
                if (wbyte == -1)
                {
                    perror("write");
                }
                else if (wbyte != total_bytes_read)
                {
                    printf("pollserver: write less the requested maybe try again\n");
                }

                if (lseek(fd_log, 0, SEEK_SET) == -1)
                {
                    perror("lseek");
                }
                rbyte = read(fd_log, buffer, D_BUFFER_SIZE * sizeof(char));
                while (rbyte > 0)
                {
                    if (send(sock, buffer, rbyte, 0) == -1)
                    {
                        perror("send");
                    }
                    rbyte = read(fd_log, buffer, D_BUFFER_SIZE * sizeof(char));
                }

                if (lseek(fd_log, 0, SEEK_END) == -1)
                {
                    perror("lseek");
                }

                // Unlock mutex after accessing shared resources
                pthread_mutex_unlock(&server_state.mutex);

                //******************
                //reset all value
                //******************
                fragment_number = 1;
                total_bytes_read = 0;
                ret = realloc(buffer, D_BUFFER_SIZE * sizeof(char));
                if (ret == NULL) {
                    perror("realloc: fail");
                    break;
                }
                buffer = ret;
            }
            else if (bytes_read == D_BUFFER_SIZE * sizeof(char))
            {
                fragment_number++;
                ret = realloc(buffer, fragment_number * D_BUFFER_SIZE * sizeof(char));
                if (ret == NULL) {
                    perror("realloc: fail");
                    break;
                }
                buffer = ret;
                total_bytes_read += bytes_read;
            }
            else
            {
                printf("need to check how to handle partial packet!\n");
            }
        }

    }

    free(buffer);
    printf("Client disconnected.\n");
    close(sock);
    kill(getpid(), SIGUSR1);
    pthread_exit(NULL);
    return NULL;
}

