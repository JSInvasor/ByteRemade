#pragma once

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

void AES_KeySchedule(const uint8_t *key, uint8_t *ekey);
void AES_Encrypt(const uint8_t *ekey, uint8_t *state);
void AES_Decrypt(const uint8_t *ekey, uint8_t *state);
void AES_Encrypt_CBC(const uint8_t *ekey, uint8_t *iv, uint8_t *buf, size_t len);
void AES_Decrypt_CBC(const uint8_t *ekey, uint8_t *iv, uint8_t *buf, size_t len);
ssize_t aes128_cbc_encrypt_with_iv(const uint8_t *key, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size);
ssize_t aes128_cbc_decrypt_with_iv(const uint8_t *key, uint8_t *inout, size_t inout_len);

char *aes_decrypt_hex_string(const char *key_hex, const char *ciphertext_hex);
char *aes_decrypt_string(const uint8_t *key, const char *ciphertext_hex);

#endif