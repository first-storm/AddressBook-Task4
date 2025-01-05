// simple_crypto.h
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// Define error codes
#define SC_SUCCESS 0
#define SC_ERR_KEY_GEN -1
#define SC_ERR_ENCRYPT -2
#define SC_ERR_DECRYPT -3
#define SC_ERR_MEMORY -4
#define SC_ERR_BASE64 -5

int generate_aes256_key(const char *password, unsigned char *key_out);

int encrypt_string(const char *plaintext, const char *password, char **ciphertext_out);

int decrypt_string(const char *ciphertext, const char *password, char **plaintext_out);
#endif
