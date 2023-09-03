#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <syslog.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// int socket(int domain, int type, int protocol);

// int bind(int socketfd, const struct sockaddr *addr, socklen_t addrlen);
// struct sockaddr {
//     sa_family_t sa_family;
//     char sa_data[14];
// }
// sockaddr_in -> sockaddr or getaddrinfo() -> use this instead.

// int listen(int sockfd, int backlog)

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

#define BACKLOG 10
#define MAXDATASIZE 1024 * 1024

static bool caught_signal = false;
static bool run_in_daemon = false;

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    printf("Signal interrupted\n");
    syslog(LOG_INFO, "Caught signal, exiting\n");

    caught_signal = true;

    errno = saved_errno;
}


// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int handle_message(const char* writefile, const char* writestr, ssize_t numbytes)
{
    int fd;
    fd = open(writefile, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd == -1) {
        syslog(LOG_ERR, "Unable to create file: %s", writefile);
        return 1;
    }

    ssize_t nr;
    nr = write(fd, writestr, numbytes);
    if (nr == -1) {
        syslog(LOG_ERR, "Unable to write %s into file: %s", writestr, writefile);
        return 1;
    } else if (nr != strlen(writestr)) {
        syslog(LOG_ERR, "Writing %s into file not complete: %s", writestr, writefile);
        return 1;
    }

    return 0;
}

int read_file(const char* readfile, char* buf) {
    int fd;

    fd = open(readfile, O_RDONLY);
    if (fd == -1) {
        syslog(LOG_ERR, "Unable to read file: %s\n", readfile);
        perror("read");
        return -1;
    }

    ssize_t ret = 0;
    ssize_t len = MAXDATASIZE;
    ssize_t totalbytes = 0;

    while (len >= 0 && (ret = read(fd, buf, len)) != 0) {
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            break;
        } else if (ret == 0) {
            break;
        }

        len -= ret;
        buf += ret;
        totalbytes += ret;
    }

    printf("Total bytes %ld\n", totalbytes);

    return totalbytes;
}

int run_server(int sockfd) {
    int new_fd;
    int rc;

    printf("Listening\n");
    rc = listen(sockfd, BACKLOG);
    if (rc != 0) {
        perror("listen");
        syslog(LOG_ERR, "listen failed");
        exit(1);
    }

    // Install signal handler here
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("Waiting for connection request.\n");

    char s[INET6_ADDRSTRLEN];

    while(!caught_signal) {
        socklen_t addr_size;
        struct sockaddr their_addr;

        addr_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }

        inet_ntop(their_addr.sa_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);
        printf("server: got connection from %s\n", s);
        syslog(LOG_INFO, "Accepted connection from %s\n", s);

        int numbytes;
        char buf[MAXDATASIZE];
        while (true) {
            numbytes = recv(new_fd, buf, MAXDATASIZE - 1, 0);
            printf("Num bytes : %d\n", numbytes);
            if (numbytes == -1) {
                perror("recv");
                close(new_fd);
                exit(1);
            } else if (numbytes == 0) {
                close(new_fd);
                syslog(LOG_INFO, "Closed connection from %s\n", s);
                break;

            } else {
                printf("Handle message\n");
                handle_message("/var/tmp/aesdsocketdata", buf, numbytes);

                char read_buf[MAXDATASIZE - 1];
                ssize_t readbytes = read_file("/var/tmp/aesdsocketdata", read_buf);
                if (readbytes == -1) {
                    printf("Read error\n");
                }

                int sentbytes = send(new_fd, read_buf, readbytes, 0);
                if (sentbytes == -1) {
                    perror("server: send");
                    syslog(LOG_ERR, "Send error\n");
                }

            }
        }
    }

    remove("/var/tmp/aesdsocketdata");
    close(sockfd);

    return 0;
}

int main(int argc, char* argv[]) {

    openlog(NULL, 0, LOG_USER);

    if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
        run_in_daemon = true;
    }

    const char* serviceport = "9000";
    struct addrinfo hints;
    struct addrinfo *servinfo;
    int yes = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int rc;
    rc = getaddrinfo(NULL, serviceport, &hints, &servinfo);
    if (rc != 0) {
        perror("getaddrinfo");
        syslog(LOG_ERR, "getaddrinfo failed\n");
        exit(1);
    }

    int sockfd;

    // Loop through all the results
    struct addrinfo* p;
    for (p = servinfo; p != NULL; p=p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("server: socket");
            syslog(LOG_ERR, "socket failed\n");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("setsockopt");
            exit(1);
        }

        rc = bind(sockfd, p->ai_addr, p->ai_addrlen);
        if (rc == -1) {
            perror("server: bind");
            continue;
        }

        break;
    }
    freeaddrinfo(servinfo);

    if (p == NULL) {
        syslog(LOG_ERR, "server: failed to bind\n");
        exit(1);
    }

    if (run_in_daemon) {
        pid_t pid;
        pid = fork();

        if (pid == -1) {
            perror("fork");
            exit(1);
        } else if (!pid) {
            // Child process
            run_server(sockfd);
        }

    } else {
        run_server(sockfd);
    }

    return 0;
}

