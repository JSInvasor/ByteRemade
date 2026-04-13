#pragma once

#ifndef RAND_H
#define RAND_H

#include <stdint.h>

uint32_t rand_next();
void init_rand();
void rand_hex(char *str, int len);
uint32_t rand_next_range(uint32_t min, uint32_t max);
void rand_str(char *str, int len);

#endif // RAND_H
