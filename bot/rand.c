#define _GNU_SOURCE

#include <time.h>
#include <unistd.h>
#include <stdint.h>

#include "headers/rand.h"

uint32_t x, y, z, w;
static char hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

uint32_t rand_next() {
    uint32_t t = x;
    t ^= t << 11;
    t ^= t >> 8;
    x = y; y = z; z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}

void init_rand() {
    uint32_t seed = (uint32_t)time(NULL) ^ getpid();
    x = seed; y = seed << 13; z = (seed >> 9) ^ 0xA5A5A5A5; w = seed ^ 0x12345678;
}

uint32_t rand_next_range(uint32_t min, uint32_t max) {
    return (rand_next() % ((max - min) + 1)) + min;
}

void rand_hex(char *str, int len) {
    while (len > 0) {
        *str++ = hex[rand_next() % 16];
        len--;

    }
}

void rand_str(char *str, int len) {
    while (len > 0) {
        if (len >= 4) {
            *((uint32_t *)str) = rand_next();
            str += sizeof(uint32_t);
            len -= sizeof(uint32_t);
        }
        else if (len >= 2) {
            *((uint16_t *)str) = rand_next() & 0xFFFF;
            str += sizeof(uint16_t);
            len -= sizeof(uint16_t);
        }
        else {
            *str++ = rand_next() & 0xFF;
            len--;
        }
    }
}
