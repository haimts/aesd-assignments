/*
** server.c -- a stream socket server demo
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "aesdsocketTypes.h"


#define D_PORT "9000"

//#define D_BUFFER_SIZE 4096

#define TEMP_OUTPUT_PATH "/var/tmp/aesdsocketdata"

extern void* handle_client(void* client_socket);
extern void* thread_timer(void* client_socket);
extern void setup_signal_handling();
extern void cleanupExitThreads(server_state_t *server_state);
extern void terminateAllThreadByForce(server_state_t *server_state);

//*****************************
// Global server state instance
//*****************************
server_state_t server_state;

// Get sockaddr, IPv4 or IPv6:
extern void*
get_in_addr(struct sockaddr *sa);

extern int parse(int argc, char **argv);

int setup_server() {
    struct addrinfo hints, *res, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Either IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // Use my IP

    if ((rv = getaddrinfo(NULL, D_PORT, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    // Loop through all the results and bind to the first we can
    for (p = res; p != NULL; p = p->ai_next) {
        if ((server_state.server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("socket");
            continue;
        }

        if (setsockopt(server_state.server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            close(server_state.server_fd);
            continue;
        }

        if (bind(server_state.server_fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("bind");
            close(server_state.server_fd);
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "Failed to bind\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    if (listen(server_state.server_fd, 10) == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    openlog(NULL, LOG_PID, LOG_USER);


    server_state.logger_fd = open(TEMP_OUTPUT_PATH, O_RDWR | O_TRUNC | O_CLOEXEC | O_CREAT | O_DSYNC,
    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (server_state.logger_fd == -1)
    {
        close(server_state.server_fd);
        fprintf(stderr, "%s on %s\n", strerror(errno), TEMP_OUTPUT_PATH);
        pthread_exit((void*)1);
    }

    if (server_state.deamon_mode)
    {
        pid_t pid;
        pid = fork();
        if (pid < 0)
        {
            close(server_state.server_fd);
            fprintf(stderr, "error while trying to enter deamon mode\n");
            exit(-1);
        }
        if (pid > 0)
        {
            close(server_state.server_fd);
            syslog(LOG_DEBUG, "starting deamon at PID=%d\n", pid);
            printf("starting deamon at PID=%d\n", pid);
            exit(0);
        }

        if (setsid() < 0)
        {
            // FAIL
            close(server_state.server_fd);
            fprintf(stderr, "error while trying to set session id\n");
            exit(-1);
        }
        //Child process in deamon mode redirect all std io to null
        close(0);       //stdin
        close(1);       //stdout
        close(2);       //stderr
        open("/dev/null", O_RDWR);
        dup(0);         //stdout
        dup(0);         //stderr
        // Create a SID for child
    }
    return server_state.server_fd;
}

int main(int argc, char** argv) {
    int new_socket;
    struct sockaddr_storage address;
    socklen_t addrlen = sizeof(address);
    char remoteIP[INET6_ADDRSTRLEN];

    // Initialize server state
    memset(&server_state, 0, sizeof(server_state_t));
    server_state.stop_server = 0;
    server_state.is_cleanup_needed = false;

    if (-1 == parse(argc, argv))
    {
        fprintf(stderr, "error getting command argument\n");
        exit(-1);
    }

    setup_signal_handling();
    server_state.server_fd = setup_server();
    pthread_mutex_init(&server_state.mutex, NULL);
    TAILQ_INIT(&server_state.head);


    // Allocate memory for the new thread node
    thread_node_t* new_node = malloc(sizeof(thread_node_t));
    if (new_node == NULL) {
        perror("malloc");
        pthread_mutex_destroy(&server_state.mutex);
        close(server_state.server_fd);
        close(server_state.logger_fd);
        exit(-1);
    }
    new_node->server = &server_state;
    printf("handle_client: argument client_socket: %p\n",new_node);
    if (pthread_create(&new_node->thread_id, NULL, thread_timer, new_node) != 0) {
        perror("pthread_create");
        free(new_node);
    } else {
        // Lock mutex before modifying shared list
        pthread_mutex_lock(&server_state.mutex);
        TAILQ_INSERT_TAIL(&server_state.head, new_node, entries);
        // Unlock mutex after modifying shared list
        pthread_mutex_unlock(&server_state.mutex);
    }

    printf("Server listening on port %s\n", D_PORT);

    while (!server_state.stop_server) {
        // clean up completed threads //TODO: [HZ: call bellow function cause massive possible memory loss]
        cleanupExitThreads(&server_state);

        // Accept a new connection
        if ((new_socket = accept(server_state.server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            if (server_state.stop_server) break;
            perror("accept");
            continue;
        }

        printf("New connection accepted.\n");

        syslog(LOG_DEBUG, "Accepted connection from %s",
                inet_ntop(address.ss_family, get_in_addr((struct sockaddr*) &address), remoteIP,
                INET6_ADDRSTRLEN));

        // Allocate memory for the new thread node
        thread_node_t* new_node = malloc(sizeof(thread_node_t));
        if (new_node == NULL) {
            perror("malloc");
            close(new_socket);
            continue;
        }
        new_node->socket_fd = new_socket;
        new_node->server = &server_state;

        if (pthread_create(&new_node->thread_id, NULL, handle_client, new_node) != 0) {
            perror("pthread_create");
            close(new_socket);
            free(new_node);
        } else {
            // Lock mutex before modifying shared list
            pthread_mutex_lock(&server_state.mutex);
            TAILQ_INSERT_TAIL(&server_state.head, new_node, entries);
            // Unlock mutex after modifying shared list
            pthread_mutex_unlock(&server_state.mutex);
        }
    }
    syslog(LOG_DEBUG,"Server starting to clean up.\n");
    // Close the server socket
    close(server_state.server_fd);

    syslog(LOG_DEBUG,"Server starting clean tailQ.\n");
    // Join all threads
    terminateAllThreadByForce(&server_state);

    syslog(LOG_DEBUG,"Server clean mutex.\n");
    // Destroy mutex
    pthread_mutex_destroy(&server_state.mutex);
    syslog(LOG_DEBUG,"Server close log.\n");
    closelog();
    printf("Server shut down gracefully.\n");
    return 0;
}
