#pragma once

#ifndef MANAGER_H
#define MANAGER_H

void init_thread_states();
void handle_command(char* command, int sock);
void cleanup_attack_threads(void);

#ifndef BArch
#define BArch "unknown"
#endif

#endif // MANAGER_H
