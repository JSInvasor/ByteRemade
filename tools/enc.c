#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

static const uint8_t rcon[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static const uint8_t sbox_table[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static const uint8_t isbox_table[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static uint8_t ct_sbox(uint8_t v) {
    uint8_t out = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t eq = (uint8_t)((i ^ v) == 0);
        uint8_t mask = 0 - eq;
        out |= sbox_table[i] & mask;
    }
    return out;
}

static uint8_t ct_isbox(uint8_t v) {
    uint8_t out = 0;
    for (int i = 0; i < 256; i++) {
        uint8_t eq = (uint8_t)((i ^ v) == 0);
        uint8_t mask = 0 - eq;
        out |= isbox_table[i] & mask;
    }
    return out;
}

static uint8_t AES_GMul(uint8_t a, uint8_t b) {
    uint8_t p = 0, i, c;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        c = a & 0x80;
        a <<= 1;
        if (c) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static void AES_AddRoundKey(const uint8_t *key, uint8_t *state) {
    for (int i = 0; i < 16; i++)
        state[i] ^= key[i];
}

static void AES_SubBytes(uint8_t *state) {
    for (int i = 0; i < 16; i++)
        state[i] = ct_sbox(state[i]);
}

static void AES_InvSubBytes(uint8_t *state) {
    for (int i = 0; i < 16; i++)
        state[i] = ct_isbox(state[i]);
}

static void AES_ShiftRows(uint8_t *state) {
    uint8_t a, b;
    a = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = a;
    a = state[2];
    b = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = a;
    state[14] = b;
    a = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = a;
}

static void AES_InvShiftRows(uint8_t *state) {
    uint8_t a, b;
    a = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = a;
    a = state[10];
    b = state[14];
    state[10] = state[2];
    state[14] = state[6];
    state[2] = a;
    state[6] = b;
    a = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = a;
}

static void AES_MixColums(uint8_t *state) {
    uint8_t s[4];
    uint8_t m[] = {2,3,1,1, 1,2,3,1, 1,1,2,3, 3,1,1,2};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            s[j] = AES_GMul(state[i*4 + 0], m[j*4 + 0]);
            s[j] ^= AES_GMul(state[i*4 + 1], m[j*4 + 1]);
            s[j] ^= AES_GMul(state[i*4 + 2], m[j*4 + 2]);
            s[j] ^= AES_GMul(state[i*4 + 3], m[j*4 + 3]);
        }
        state[i*4 + 0] = s[0];
        state[i*4 + 1] = s[1];
        state[i*4 + 2] = s[2];
        state[i*4 + 3] = s[3];
    }
}

static void AES_InvMixColums(uint8_t *state) {
    uint8_t s[4];
    uint8_t m[] = {14,11,13,9, 9,14,11,13, 13,9,14,11, 11,13,9,14};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            s[j] = AES_GMul(state[i*4 + 0], m[j*4 + 0]);
            s[j] ^= AES_GMul(state[i*4 + 1], m[j*4 + 1]);
            s[j] ^= AES_GMul(state[i*4 + 2], m[j*4 + 2]);
            s[j] ^= AES_GMul(state[i*4 + 3], m[j*4 + 3]);
        }
        state[i*4 + 0] = s[0];
        state[i*4 + 1] = s[1];
        state[i*4 + 2] = s[2];
        state[i*4 + 3] = s[3];
    }
}

void AES_KeySchedule(const uint8_t *key, uint8_t *ekey) {
    memset(ekey, 0, 176);
    memcpy(ekey, key, 16);
    uint8_t *pk = ekey;
    uint8_t *ck = ekey + 16;
    for (int round = 0; round < 10; round++) {
        ck[0] = pk[13];
        ck[1] = pk[14];
        ck[2] = pk[15];
        ck[3] = pk[12];
        ck[0] = ct_sbox(ck[0]);
        ck[1] = ct_sbox(ck[1]);
        ck[2] = ct_sbox(ck[2]);
        ck[3] = ct_sbox(ck[3]);
        ck[0] ^= rcon[round];
        ck[0] ^= pk[0];
        ck[1] ^= pk[1];
        ck[2] ^= pk[2];
        ck[3] ^= pk[3];
        for (int j = 4; j < 16; j += 4) {
            ck[j + 0] = ck[j - 4 + 0] ^ pk[j + 0];
            ck[j + 1] = ck[j - 4 + 1] ^ pk[j + 1];
            ck[j + 2] = ck[j - 4 + 2] ^ pk[j + 2];
            ck[j + 3] = ck[j - 4 + 3] ^ pk[j + 3];
        }
        pk = ck;
        ck += 16;
    }
}

void AES_Encrypt(const uint8_t *ekey, uint8_t *state) {
    AES_AddRoundKey((uint8_t*)ekey, state);
    for (uint8_t round = 1; round <= 9; round++) {
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_MixColums(state);
        AES_AddRoundKey((uint8_t*)(ekey + round * 16), state);
    }
    AES_SubBytes(state);
    AES_ShiftRows(state);
    AES_AddRoundKey((uint8_t*)(ekey + 160), state);
}

void AES_Decrypt(const uint8_t *ekey, uint8_t *state) {
    AES_AddRoundKey((uint8_t*)(ekey + 160), state);
    for (int round = 9; round > 0; round--) {
        AES_InvShiftRows(state);
        AES_InvSubBytes(state);
        AES_AddRoundKey((uint8_t*)(ekey + round * 16), state);
        AES_InvMixColums(state);
    }
    AES_InvShiftRows(state);
    AES_InvSubBytes(state);
    AES_AddRoundKey((uint8_t*)ekey, state);
}

static size_t pkcs7_pad(uint8_t *out, const uint8_t *in, size_t in_len) {
    size_t pad = 16 - (in_len % 16);
    size_t out_len = in_len + pad;
    memcpy(out, in, in_len);
    for (size_t i = 0; i < pad; i++)
        out[in_len + i] = (uint8_t)pad;
    return out_len;
}

static size_t pkcs7_unpad(uint8_t *buf, size_t len) {
    if (len == 0 || (len % 16) != 0)
        return (size_t)-1;
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > 16)
        return (size_t)-1;
    uint8_t bad = 0;
    for (size_t i = 0; i < pad; i++) {
        bad |= buf[len - 1 - i] ^ pad;
    }
    if (bad)
        return (size_t)-1;
    return len - pad;
}

static void xor16(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; i++)
        dst[i] = a[i] ^ b[i];
}

void AES_Encrypt_CBC(const uint8_t *ekey, uint8_t *iv, uint8_t *buf, size_t len) {
    uint8_t tmp[16];
    for (size_t offset = 0; offset < len; offset += 16) {
        xor16(tmp, &buf[offset], iv);
        AES_Encrypt(ekey, tmp);
        memcpy(&buf[offset], tmp, 16);
        memcpy(iv, tmp, 16);
    }
}

void AES_Decrypt_CBC(const uint8_t *ekey, uint8_t *iv, uint8_t *buf, size_t len) {
    uint8_t prev[16];
    uint8_t tmp[16];
    uint8_t ctmp[16];
    memcpy(prev, iv, 16);
    for (size_t offset = 0; offset < len; offset += 16) {
        memcpy(ctmp, &buf[offset], 16);
        memcpy(tmp, &buf[offset], 16);
        AES_Decrypt(ekey, tmp);
        xor16(&buf[offset], tmp, prev);
        memcpy(prev, ctmp, 16);
    }
}

int get_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, len);
    close(fd);
    if (r != (ssize_t)len) return -1;
    return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        int hi, lo;
        char c = hex[i*2];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;
        c = hex[i*2 + 1];
        if (c >= '0' && c <= '9') lo = c - '0';
        else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
        else return -1;
        out[i] = (hi << 4) | lo;
    }
    return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    const char *hex_chars = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        hex[i*2] = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[i*2 + 1] = hex_chars[bytes[i] & 0xF];
    }
    hex[len * 2] = '\0';
}

ssize_t aes128_cbc_encrypt_with_iv(const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size) {
    uint8_t ekey[176];
    AES_KeySchedule(key, ekey);

    size_t max_needed = in_len + 16;
    if (out_size < 16 + max_needed) return -1;
    uint8_t *iv = out;
    if (get_random_bytes(iv, 16) != 0) return -1;

    uint8_t *ct = out + 16;
    size_t padded_len = pkcs7_pad(ct, in, in_len);

    uint8_t iv_local[16];
    memcpy(iv_local, iv, 16);
    AES_Encrypt_CBC(ekey, iv_local, ct, padded_len);
    return (ssize_t)(16 + padded_len);
}

ssize_t aes128_cbc_decrypt_with_iv(const uint8_t *key, uint8_t *inout, size_t inout_len) {
    if (inout_len < 16 || ((inout_len - 16) % 16) != 0) return -1;
    uint8_t ekey[176];
    AES_KeySchedule(key, ekey);

    uint8_t iv[16];
    memcpy(iv, inout, 16);
    uint8_t *ct = inout + 16;
    size_t ct_len = inout_len - 16;

    AES_Decrypt_CBC(ekey, iv, ct, ct_len);

    size_t plain_len = pkcs7_unpad(ct, ct_len);
    if (plain_len == (size_t)-1) return -1;

    memmove(inout, ct, plain_len);
    return (ssize_t)plain_len;
}

char *aes_encrypt_string(const uint8_t *key, const char *plaintext) {
    size_t in_len = strlen(plaintext);
    size_t max_out_len = 16 + in_len + 16;
    
    uint8_t *buffer = malloc(max_out_len);
    if (!buffer) return NULL;

    ssize_t result = aes128_cbc_encrypt_with_iv(key, (const uint8_t*)plaintext, in_len, buffer, max_out_len);
    if (result < 0) {
        free(buffer);
        return NULL;
    }

    char *hex = malloc(result * 2 + 1);
    if (!hex) {
        free(buffer);
        return NULL;
    }

    bytes_to_hex(buffer, result, hex);
    free(buffer);
    return hex;
}

char *aes_encrypt_hex_string(const char *key_hex, const char *plaintext) {
    uint8_t key[16];
    if (hex_to_bytes(key_hex, key, 16) != 0) return NULL;
    return aes_encrypt_string(key, plaintext);
}

char *aes_decrypt_string(const uint8_t *key, const char *ciphertext_hex) {
    size_t hex_len = strlen(ciphertext_hex);
    if (hex_len % 2 != 0 || hex_len < 32) {
        return NULL;
    }

    size_t data_len = hex_len / 2;
    uint8_t *data = malloc(data_len);
    if (!data) {
        return NULL;
    }

    if (hex_to_bytes(ciphertext_hex, data, data_len) != 0) {
        free(data);
        return NULL;
    }

    ssize_t result = aes128_cbc_decrypt_with_iv(key, data, data_len);
    if (result < 0) {
        free(data);
        return NULL;
    }

    char *plaintext = malloc(result + 1);
    if (!plaintext) {
        free(data);
        return NULL;
    }
    
    memcpy(plaintext, data, result);
    plaintext[result] = '\0';
    
    free(data);
    return plaintext;
}

char *aes_decrypt_hex_string(const char *key_hex, const char *ciphertext_hex) {
    uint8_t key[16];
    if (hex_to_bytes(key_hex, key, 16) != 0) {
        return NULL;
    }
    char *result = aes_decrypt_string(key, ciphertext_hex);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s encrypt <text> <key>\n", argv[0]);
        fprintf(stderr, "  %s decrypt <hex> <key>\n", argv[0]);
        fprintf(stderr, "  %s encrypt-hex <text> <key>  (returns hex string)\n", argv[0]);
        fprintf(stderr, "  %s decrypt-hex <hex> <key>   (returns plaintext)\n", argv[0]);
        fprintf(stderr, "\nKey must be 32 hex characters (16 bytes)\n");
        return 1;
    }

    uint8_t key[16];
    if (argc >= 4) {
        if (hex_to_bytes(argv[3], key, 16) != 0) {
            fprintf(stderr, "Invalid hex key (must be 32 hex chars)\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Error: missing hex key (use 32 hex chars)\n");
        return 1;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        const char *text = argv[2];
        size_t text_len = strlen(text);
        size_t max_out = text_len + 32;
        uint8_t *out = malloc(max_out);
        if (!out) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }

        uint8_t ekey[176];
        AES_KeySchedule(key, ekey);

        uint8_t *iv = out;
        if (get_random_bytes(iv, 16) != 0) {
            fprintf(stderr, "Failed to generate IV\n");
            free(out);
            return 1;
        }

        uint8_t *ct = out + 16;
        size_t padded_len = pkcs7_pad(ct, (uint8_t*)text, text_len);
        uint8_t iv_local[16];
        memcpy(iv_local, iv, 16);
        AES_Encrypt_CBC(ekey, iv_local, ct, padded_len);

        size_t total_len = 16 + padded_len;
        for (size_t i = 0; i < total_len; i++) {
            printf("%02x", out[i]);
        }
        printf("\n");

        free(out);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        const char *hex = argv[2];
        size_t hex_len = strlen(hex);
        if (hex_len % 2 != 0 || hex_len < 32) {
            fprintf(stderr, "Invalid ciphertext\n");
            return 1;
        }

        size_t data_len = hex_len / 2;
        uint8_t *data = malloc(data_len);
        if (!data) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }

        if (hex_to_bytes(hex, data, data_len) != 0) {
            fprintf(stderr, "Invalid hex string\n");
            free(data);
            return 1;
        }

        uint8_t ekey[176];
        AES_KeySchedule(key, ekey);

        uint8_t iv[16];
        memcpy(iv, data, 16);
        uint8_t *ct = data + 16;
        size_t ct_len = data_len - 16;

        AES_Decrypt_CBC(ekey, iv, ct, ct_len);
        size_t plain_len = pkcs7_unpad(ct, ct_len);

        if (plain_len == (size_t)-1) {
            fprintf(stderr, "Decryption failed (wrong key or corrupted data)\n");
            free(data);
            return 1;
        }

        fwrite(ct, 1, plain_len, stdout);
        printf("\n");

        free(data);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        return 1;
    }

    return 0;
}