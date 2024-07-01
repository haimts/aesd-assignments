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
#include <getopt.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "aesdsocketTypes.h"

#define D_CLEANUP_CLIENTTRASHHOLD 1

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)          \
    for ((var) = TAILQ_FIRST((head));               \
        (var) && ((tvar) = TAILQ_NEXT((var), field), 1);        \
        (var) = (tvar))

extern server_state_t server_state;

void handle_signal(int signal, siginfo_t *info, void *context)
{
    if (context)
    {
        
    }
    printf("Received signal %d, code %d, shutting down...\n", signal, info->si_code);
    server_state.stop_server = 1;
}

void handle_sigusr1(int signal, siginfo_t *info, void *context)
{
    static unsigned int thrashhold = 1;
    if (context)
    {
        
    }
    printf("Received signal %d, code %d, cleaning up dead threads...\n", signal, info->si_code);
    if (thrashhold >= D_CLEANUP_CLIENTTRASHHOLD) {
        server_state.is_cleanup_needed = 1;
    }
    else
    {
        thrashhold++;
    }
}
void setup_signal_handling()
{
    struct sigaction sa;
    sa.sa_sigaction = handle_signal;
    sa.sa_flags = SA_SIGINFO;
    sigfillset(&sa.sa_mask);
    sigdelset(&sa.sa_mask, SIGINT);
    sigdelset(&sa.sa_mask, SIGTERM);
    sigdelset(&sa.sa_mask, SIGUSR1);

    if (sigaction(SIGINT, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    sa.sa_sigaction = handle_sigusr1;
    if (sigaction(SIGUSR1, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
    pthread_sigmask(SIG_SETMASK, &sa.sa_mask, NULL);
}

// Get sockaddr, IPv4 or IPv6:
void*
get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*) sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

int parse(int argc, char **argv)
{
    int c;
    int option_index = 0;
    while (1)
    {
        static struct option long_option[] =
            {
                { "demon", no_argument, 0, 0 },
                { 0, 0, 0, 0 } };
        c = getopt_long(argc, argv, "d", long_option, &option_index);
        if (c == -1)
        {
            break;
        }

        switch (c)
        {
        case 'd':
            server_state.deamon_mode = true;
            break;
        default:
            syslog(LOG_DEBUG, "Invalid argument\n");
            return -1;
            break;
        }
    }
    return 0;
}

void removeTailQElement(server_state_t *server_state, thread_node_t *node)
{
    // Lock mutex before modifying shared list
    pthread_mutex_lock(&server_state->mutex);
    TAILQ_REMOVE(&server_state->head, node, entries);
    // Unlock mutex after modifying shared list
    pthread_mutex_unlock(&server_state->mutex);
    free(node);
    printf("handle_client: remove client_socket: %p\n", node);
}

//TODO: [HZ: call bellow function cause massive possible memory loss]
void cleanupExitThreads(server_state_t *server_state)
{
    // clean up completed threads
    if (server_state->is_cleanup_needed)
    {
#if 0
        // Join joinable threads
        thread_node_t *node;
        thread_node_t *node_t = NULL;
        TAILQ_FOREACH_SAFE(node,&server_state->head, entries, node_t)
        {
            if (-1 == pthread_tryjoin_np(node->thread_id, NULL))
            {
                continue;
            }
            // Lock mutex before modifying shared list
            removeTailQElement(server_state, node);
        }
#endif
        server_state->is_cleanup_needed = false;
    }
}

void terminateAllThreadByForce(server_state_t *server_state)
{
    // Join all threads
    thread_node_t *node;
    while ((node = TAILQ_FIRST(&server_state->head)) != NULL)
    {
        if (-1 == pthread_tryjoin_np(node->thread_id, NULL))
        {
            sched_yield();
            pthread_cancel(node->thread_id);
            pthread_join(node->thread_id, NULL);
        }
        removeTailQElement(server_state, node);
    }
}

void*
thread_timer(void *args)
{
    char argv[] =
        { "%Y%m%2d%T" };
    server_state_t *server_common_variables_p = ((thread_node_t*) args)->server;
    int fd_log = ((thread_node_t*) args)->server->logger_fd;
    //free(args);
    while (!server_common_variables_p->stop_server)
    {
        char outstr[200] = {"timestamp:"};
        const int outstrlen = strlen(outstr);
        time_t t;
        struct tm *tmp;
        int rc;

        if (0 != sleep(10))
            break;
        t = time(NULL);
        tmp = localtime(&t);
        if (tmp == NULL)
        {
            perror("localtime");
            exit(EXIT_FAILURE);
        }
        if (strftime(outstr + outstrlen , sizeof(outstr) - outstrlen, argv, tmp) == 0)
        {
            fprintf(stderr, "strftime returned 0");
            exit(EXIT_FAILURE);
        }
        pthread_mutex_lock(&server_common_variables_p->mutex);
        outstr[strlen(outstr + 1)] = '\0';
        outstr[strlen(outstr)] = '\n';
        rc = write(fd_log, outstr, strlen(outstr));
        pthread_mutex_unlock(&server_common_variables_p->mutex);
        if (rc <= 0){
            break;
        }
    }


    pthread_exit(NULL);
    return NULL;
}

