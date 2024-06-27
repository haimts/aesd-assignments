
// Define a struct to hold server state
typedef struct {
    int server_fd;                           // Server file descriptor
    int logger_fd;                           // DB file descriptor
    bool deamon_mode;                        // In deamon mode
    bool is_cleanup_needed;                  // In deamon mode
    volatile sig_atomic_t stop_server;       // Flag to stop the server
    pthread_mutex_t mutex;                   // Mutex for synchronization
    TAILQ_HEAD(tailhead, thread_node) head;  // Head for thread nodes
} server_state_t;

// Define a struct to hold thread information
typedef struct thread_node {
    pthread_t thread_id;
    int       socket_fd;
    server_state_t *server;
    TAILQ_ENTRY(thread_node) entries;
} thread_node_t;
