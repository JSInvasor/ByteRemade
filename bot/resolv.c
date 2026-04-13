#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#include "headers/resolv.h"

#define MAX_RESOLVE_ATTEMPTS 5
#define RESOLVE_BASE_DELAY 2

char* resolv_with_retry(const char* domain) {
    if (!domain) return NULL;
    
    static char ip_str[INET_ADDRSTRLEN];
    struct addrinfo hints, *result;
    
    for (int attempt = 1; attempt <= MAX_RESOLVE_ATTEMPTS; attempt++) {
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        int status = getaddrinfo(domain, NULL, &hints, &result);
        if (status == 0) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
            
            if (inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN)) {
                freeaddrinfo(result);
                return ip_str;
            }
            freeaddrinfo(result);
        }

        if (attempt < MAX_RESOLVE_ATTEMPTS) {
            int delay = RESOLVE_BASE_DELAY * (1 << (attempt - 1));
            int jitter = rand() % (delay / 2 + 1);
            int total_delay = delay + jitter;

            if (total_delay > 30) total_delay = 30;

            sleep(total_delay);
        }
    }

    return NULL;
}

char* resolv(const char* domain) {
    return resolv_with_retry(domain);
}
