#pragma once

#ifdef DEBUG
#include <stdio.h>
#endif

#ifdef DEBUG
#define DEBUG_PRINT(msg, ...) printf(msg, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(msg, ...)
#endif
