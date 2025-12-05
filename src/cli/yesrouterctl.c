/**
 * @file yesrouterctl.c
 * @brief YESRouter CLI Client (VPP-style with telnet protocol)
 *
 * Connects to yesrouter daemon via Unix socket for CLI access.
 * Implements telnet protocol for full readline support (tab, arrows, backspace).
 *
 * Usage:
 *   yesrouterctl                    # Interactive mode
 *   yesrouterctl show interfaces    # Single command
 *   yesrouterctl -s /path/to/socket # Custom socket path
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#define DEFAULT_SOCKET_PATH "/run/yesrouter/cli.sock"
#define BUFFER_SIZE 4096

/* Telnet protocol constants (from VPP) */
#define IAC 255 /* Interpret As Command */
#define DONT 254
#define DO 252
#define WONT 253
#define WILL 251
#define SB 250 /* Subnegotiation Begin */
#define SE 240 /* Subnegotiation End */

#define TELOPT_TTYPE 24 /* Terminal Type */
#define TELOPT_NAWS 31  /* Negotiate About Window Size */
#define TELOPT_ECHO 1   /* Echo */

static struct termios orig_tio;
static volatile int window_resized = 0;

/**
 * Connect to yesrouter daemon
 */
static int connect_to_daemon(const char *socket_path)
{
    int sock_fd;
    struct sockaddr_un addr;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to yesrouter at %s: %s\n", socket_path, strerror(errno));
        fprintf(stderr, "\nIs yesrouter running as a daemon?\n");
        fprintf(stderr, "Try: sudo yesrouter -d\n");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

/**
 * Signal handler for window resize (SIGWINCH)
 */
static void signal_handler_winch(int signum)
{
    (void)signum;
    window_resized = 1;
}

/**
 * Signal handler for terminal signals - restore terminal on exit
 */
static void signal_handler_term(int signum)
{
    (void)signum;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_tio);
}

/**
 * Set terminal to raw mode (character-by-character, no echo)
 */
static int set_raw_mode(void)
{
    struct termios tio;

    /* Save original settings */
    if (tcgetattr(STDIN_FILENO, &orig_tio) < 0) {
        perror("tcgetattr");
        return -1;
    }

    /* Modify for raw mode */
    tio = orig_tio;
    tio.c_lflag &= ~(ECHO | ICANON | IEXTEN); /* No echo, no canonical, no extended */
    tio.c_cc[VMIN] = 1;                       /* 1 byte at a time */
    tio.c_cc[VTIME] = 0;                      /* No timer */

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio) < 0) {
        perror("tcsetattr");
        return -1;
    }

    return 0;
}

/**
 * Restore terminal to original mode
 */
static void restore_terminal(void)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_tio);
}

/**
 * Send terminal type via telnet protocol
 */
static void send_ttype(int sock_fd)
{
    char *term = getenv("TERM");
    if (!term)
        term = "xterm";

    char buf[256];
    int len = snprintf(buf, sizeof(buf), "%c%c%c%c%s%c%c", IAC, SB, TELOPT_TTYPE, 0, term, IAC, SE);
    ssize_t n = write(sock_fd, buf, len);
    (void)n; /* Ignore */
}

/**
 * Send window size via telnet NAWS option
 */
static void send_naws(int sock_fd)
{
    struct winsize ws;

    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) {
        return; /* Ignore errors */
    }

    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%c%c%c%c%c%c%c%c%c", IAC, SB, TELOPT_NAWS,
                       (ws.ws_col >> 8) & 0xff, ws.ws_col & 0xff, (ws.ws_row >> 8) & 0xff,
                       ws.ws_row & 0xff, IAC, SE);
    ssize_t n = write(sock_fd, buf, len);
    (void)n; /* Ignore */
}

/**
 * Process IAC (telnet) control codes from daemon output
 * Strips IAC sequences and handles negotiation
 * Returns new length of processed buffer
 */
static int process_iac(int sock_fd, unsigned char *rx_buf, int rx_buf_len, int *sent_ttype)
{
    int i = 0;
    int j = 0;

    while (i < rx_buf_len) {
        if (rx_buf[i] == IAC) {
            if (i + 1 >= rx_buf_len)
                break;

            if (rx_buf[i + 1] == SB) {
                /* Subnegotiation */
                if (i + 2 >= rx_buf_len)
                    break;

                unsigned char opt = rx_buf[i + 2];
                i += 3;

                /* Skip until SE */
                while (i < rx_buf_len && rx_buf[i] != IAC) {
                    i++;
                }
                i += 2; /* Skip IAC SE */

                /* Respond to option requests */
                if (opt == TELOPT_TTYPE) {
                    send_ttype(sock_fd);
                    *sent_ttype = 1;
                } else if (opt == TELOPT_NAWS) {
                    send_naws(sock_fd);
                }
            } else {
                /* DO/DONT/WILL/WONT - ignore */
                i += 3;
            }
        } else {
            /* Regular character - copy to output */
            rx_buf[j++] = rx_buf[i++];
        }
    }

    return j; /* New length */
}

/**
 * Execute single command and exit
 */
static int execute_single_command(int sock_fd, int argc, char **argv, int start_idx)
{
    char command[1024] = "";
    char buffer[BUFFER_SIZE];
    int bytes_read;

    /* Build command from arguments */
    for (int i = start_idx; i < argc; i++) {
        if (i > start_idx) {
            strcat(command, " ");
        }
        strncat(command, argv[i], sizeof(command) - strlen(command) - 1);
    }

    /* Send command */
    strcat(command, "\n");
    if (write(sock_fd, command, strlen(command)) < 0) {
        fprintf(stderr, "Failed to send command: %s\n", strerror(errno));
        return -1;
    }

    /* Read and display response */
    while ((bytes_read = read(sock_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);

        /* Simple heuristic: if we see a prompt at the end, we're done */
        if (strstr(buffer, "# ") != NULL) {
            break;
        }

        /* Also break on very short reads (likely end of output) */
        if (bytes_read < 100) {
            usleep(10000); /* Wait a bit for any remaining data */
            fd_set readfds;
            struct timeval tv = {0, 50000}; /* 50ms timeout */
            FD_ZERO(&readfds);
            FD_SET(sock_fd, &readfds);
            if (select(sock_fd + 1, &readfds, NULL, NULL, &tv) == 0) {
                break; /* No more data */
            }
        }
    }

    if (bytes_read < 0) {
        fprintf(stderr, "Read error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Interactive mode - VPP-style with epoll and telnet protocol
 */
static int interactive_mode(int sock_fd)
{
    struct epoll_event event, events[2];
    struct sigaction sa;
    int efd = -1;
    int is_interactive = isatty(STDIN_FILENO);
    int sent_ttype = 0;
    int error = 0;

    if (!is_interactive) {
        fprintf(stderr, "stdin is not a terminal\n");
        return -1;
    }

    /* Set up signal handlers */
    memset(&sa, 0, sizeof(sa));

    /* Window resize handler */
    sa.sa_handler = signal_handler_winch;
    if (sigaction(SIGWINCH, &sa, 0) < 0) {
        perror("sigaction SIGWINCH");
        return -1;
    }

    /* Terminal signal handler */
    sa.sa_handler = signal_handler_term;
    if (sigaction(SIGTERM, &sa, 0) < 0) {
        perror("sigaction SIGTERM");
        return -1;
    }

    /* Set terminal to raw mode */
    if (set_raw_mode() < 0) {
        return -1;
    }

    /* Create epoll instance */
    efd = epoll_create1(0);
    if (efd < 0) {
        perror("epoll_create1");
        error = -1;
        goto cleanup;
    }

    /* Register stdin */
    event.events = EPOLLIN | EPOLLPRI | EPOLLERR;
    event.data.fd = STDIN_FILENO;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, STDIN_FILENO, &event) != 0) {
        if (errno != EPERM) { /* EPERM means stdin is not pollable */
            perror("epoll_ctl stdin");
            error = -1;
            goto cleanup;
        }
    }

    /* Register socket */
    event.events = EPOLLIN | EPOLLPRI | EPOLLERR;
    event.data.fd = sock_fd;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, sock_fd, &event) != 0) {
        perror("epoll_ctl socket");
        error = -1;
        goto cleanup;
    }

    /* Main event loop */
    while (1) {
        int n;

        /* Handle window resize */
        if (window_resized) {
            window_resized = 0;
            send_naws(sock_fd);
        }

        /* Wait for events */
        n = epoll_wait(efd, events, 2, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue; /* Interrupted by signal */
            perror("epoll_wait");
            error = -1;
            break;
        }

        if (n == 0)
            continue;

        /* Process events */
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == STDIN_FILENO) {
                /* Input from user - forward to socket */
                unsigned char buf[256];

                ssize_t nr = read(STDIN_FILENO, buf, sizeof(buf));
                if (nr > 0) {
                    ssize_t nw = write(sock_fd, buf, nr);
                    if (nw < nr) {
                        error = -1;
                        goto cleanup;
                    }
                } else if (nr == 0) {
                    /* EOF */
                    goto cleanup;
                }
            } else if (events[i].data.fd == sock_fd) {
                /* Output from daemon */
                unsigned char rx_buf[BUFFER_SIZE];

                ssize_t nr = read(sock_fd, rx_buf, sizeof(rx_buf));
                if (nr <= 0) {
                    /* Connection closed */
                    goto cleanup;
                }

                /* Process telnet IAC codes */
                int processed_len = process_iac(sock_fd, rx_buf, nr, &sent_ttype);

                /* Write processed output to stdout */
                if (processed_len > 0) {
                    ssize_t nw = write(STDOUT_FILENO, rx_buf, processed_len);
                    (void)nw;
                }
            }
        }
    }

cleanup:
    if (efd >= 0) {
        close(efd);
    }

    restore_terminal();
    return error;
}

/**
 * Print usage
 */
static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS] [COMMAND...]\n", prog);
    printf("\nOptions:\n");
    printf("  -s PATH     Unix socket path (default: %s)\n", DEFAULT_SOCKET_PATH);
    printf("  -h          Display this help message\n");
    printf("\nExamples:\n");
    printf("  %s                        # Interactive mode\n", prog);
    printf("  %s show interfaces        # Single command\n", prog);
    printf("  %s show nat config        # Show NAT configuration\n", prog);
    printf("  %s -s /tmp/cli.sock       # Custom socket path\n", prog);
    printf("\n");
}

/**
 * Main entry point
 */
int main(int argc, char *argv[])
{
    const char *socket_path = DEFAULT_SOCKET_PATH;
    int sock_fd;
    int opt;
    int command_start_idx = 1;

    /* Parse options */
    while ((opt = getopt(argc, argv, "s:h")) != -1) {
        switch (opt) {
        case 's':
            socket_path = optarg;
            command_start_idx += 2;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Connect to daemon */
    sock_fd = connect_to_daemon(socket_path);
    if (sock_fd < 0) {
        return 1;
    }

    /* Determine mode: single command or interactive */
    if (optind < argc) {
        /* Single command mode */
        int ret = execute_single_command(sock_fd, argc, argv, optind);
        close(sock_fd);
        return ret;
    } else {
        /* Interactive mode */
        int ret = interactive_mode(sock_fd);
        close(sock_fd);
        return ret;
    }
}
