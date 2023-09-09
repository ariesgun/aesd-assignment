#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <pthread.h>

#define FILE_DESTINATION_PATH "/dev/aesdchar"

struct thread_data {
    struct sockaddr their_addr;
    int new_fd;
    pthread_mutex_t* mutex;
    bool done;
};

struct timer_thread_data {
    pthread_mutex_t* mutex;
    int log_timer_second;
};


struct slist_data_s {
    pthread_t thread_id;
    struct thread_data* params;
    SLIST_ENTRY(slist_data_s) entries;
};
