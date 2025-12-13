/**
 * @file yesrouter_cli.c
 * @brief YESRouter CLI Client - connects to daemon via Unix socket
 *
 * Usage: yesrouter [command]
 *   No args: interactive mode
 *   With args: execute command and exit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <sys/select.h>
#include <fcntl.h>

#define SOCKET_PATH "/run/yesrouter/cli.sock"
#define BUF_SIZE 4096

static int g_sock_fd = -1;
static struct termios g_orig_termios;
static int g_raw_mode = 0;
static volatile int g_running = 1;

static void cleanup(void)
{
    if (g_raw_mode) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
        g_raw_mode = 0;
    }
    if (g_sock_fd >= 0) {
        close(g_sock_fd);
        g_sock_fd = -1;
    }
}

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    cleanup();
    exit(0);
}

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int connect_to_daemon(void)
{
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to %s: %s\n", SOCKET_PATH, strerror(errno));
        fprintf(stderr, "Is yesrouter daemon running?\n");
        close(fd);
        return -1;
    }

    return fd;
}

static int run_single_command(int argc, char *argv[])
{
    char cmd[BUF_SIZE] = {0};
    char buf[BUF_SIZE];
    int i;
    ssize_t n;
    struct timeval tv;
    fd_set fds;

    g_sock_fd = connect_to_daemon();
    if (g_sock_fd < 0)
        return 1;

    /* Build command from args */
    for (i = 1; i < argc; i++) {
        if (i > 1) strcat(cmd, " ");
        strcat(cmd, argv[i]);
    }
    strcat(cmd, "\n");

    /* Wait for banner/prompt and discard */
    tv.tv_sec = 0; tv.tv_usec = 200000;
    FD_ZERO(&fds); FD_SET(g_sock_fd, &fds);
    while (select(g_sock_fd + 1, &fds, NULL, NULL, &tv) > 0) {
        n = recv(g_sock_fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        FD_ZERO(&fds); FD_SET(g_sock_fd, &fds);
        tv.tv_sec = 0; tv.tv_usec = 50000;
    }

    /* Send command */
    if (send(g_sock_fd, cmd, strlen(cmd), 0) < 0) {
        perror("send");
        cleanup();
        return 1;
    }

    /* Read response with timeout */
    int got_prompt = 0;
    while (!got_prompt) {
        FD_ZERO(&fds);
        FD_SET(g_sock_fd, &fds);
        tv.tv_sec = 2; tv.tv_usec = 0;

        if (select(g_sock_fd + 1, &fds, NULL, NULL, &tv) <= 0) {
            break; /* Timeout or error */
        }

        n = recv(g_sock_fd, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';

        /* Print output, filter prompts */
        char *p = buf;
        while (*p) {
            char *nl = strchr(p, '\n');
            if (nl) *nl = '\0';

            /* Check for prompt */
            if (strstr(p, "Router>") || strstr(p, "Router#")) {
                got_prompt = 1;
            } else if (strlen(p) > 0) {
                printf("%s\n", p);
            }

            if (!nl) break;
            p = nl + 1;
        }
    }

    /* Send exit and close */
    send(g_sock_fd, "exit\n", 5, MSG_NOSIGNAL);
    cleanup();
    return 0;
}

static int run_interactive(void)
{
    fd_set fds;
    char buf[BUF_SIZE];
    ssize_t n;
    int maxfd;
    struct termios raw;

    g_sock_fd = connect_to_daemon();
    if (g_sock_fd < 0)
        return 1;

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Enable raw terminal mode for immediate character processing */
    /* This is similar to cfmakeraw but preserves output processing */
    if (isatty(STDIN_FILENO)) {
        tcgetattr(STDIN_FILENO, &g_orig_termios);
        raw = g_orig_termios;
        /* Disable canonical mode, echo, and signals */
        raw.c_lflag &= ~(ECHO | ICANON | IEXTEN);
        /* Keep input processing minimal but handle CR correctly */
        raw.c_iflag &= ~(INPCK | ISTRIP | IXON);
        /* Keep output processing for proper newlines */
        /* raw.c_oflag stays unchanged */
        raw.c_cflag |= (CS8);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
        g_raw_mode = 1;
    }

    set_nonblocking(g_sock_fd);
    set_nonblocking(STDIN_FILENO);

    printf("Connected to YESRouter daemon\r\n");
    printf("Type 'exit' or Ctrl+C to disconnect\r\n\r\n");

    while (g_running) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(g_sock_fd, &fds);
        maxfd = (g_sock_fd > STDIN_FILENO) ? g_sock_fd : STDIN_FILENO;

        struct timeval tv = {1, 0};
        int ret = select(maxfd + 1, &fds, NULL, NULL, &tv);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Data from socket -> stdout */
        if (FD_ISSET(g_sock_fd, &fds)) {
            n = recv(g_sock_fd, buf, sizeof(buf) - 1, 0);
            if (n <= 0) {
                printf("\nConnection closed\n");
                break;
            }
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }

        /* Data from stdin -> socket */
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
            if (n <= 0) {
                break;
            }
            buf[n] = '\0';

            /* Check for exit */
            if (strncmp(buf, "exit", 4) == 0 || strncmp(buf, "quit", 4) == 0) {
                send(g_sock_fd, "exit\n", 5, 0);
                break;
            }

            if (send(g_sock_fd, buf, n, 0) < 0) {
                perror("send");
                break;
            }
        }
    }

    cleanup();
    return 0;
}

static void print_usage(const char *prog)
{
    printf("YESRouter CLI Client\n\n");
    printf("Usage: %s [command]\n\n", prog);
    printf("Options:\n");
    printf("  (no args)     Interactive mode\n");
    printf("  <command>     Execute command and exit\n");
    printf("  -h, --help    Show this help\n");
    printf("\nExamples:\n");
    printf("  %s                          # Interactive mode\n", prog);
    printf("  %s show interfaces          # Single command\n", prog);
    printf("  %s show nat statistics      # Single command\n", prog);
    printf("  %s enable                   # Enter privileged mode\n", prog);
}

int main(int argc, char *argv[])
{
    /* Help */
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    /* Single command mode */
    if (argc > 1) {
        return run_single_command(argc, argv);
    }

    /* Interactive mode */
    return run_interactive();
}
