// 几乎全是AI教的（
#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 全局调试变量
int DEBUG = 1;

// 日志宏定义
#define LOG(fmt, ...) \
    do { if (DEBUG) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while(0)

// 从密码生成AES-256密钥
int generate_aes256_key(const char *password, unsigned char *key_out) {
    LOG("Entering generate_aes256_key");
    
    if (!password || !key_out) {
        LOG("Error: Invalid password or key_out is NULL");
        return SC_ERR_KEY_GEN;
    }
    LOG("Password and key_out are valid");

    // 使用SHA-256哈希密码
    LOG("Generating SHA-256 hash of the password");
    if (!SHA256((unsigned char*)password, strlen(password), key_out)) {
        LOG("Error: SHA256 hashing failed");
        return SC_ERR_KEY_GEN;
    }
    LOG("SHA-256 hash generated successfully");
    LOG("Exiting generate_aes256_key with success");
    return SC_SUCCESS;
}

// Base64编码
char* base64_encode(const unsigned char* buffer, size_t length) {
    LOG("Entering base64_encode with buffer length: %zu", length);
    
    BUF_MEM *buffer_ptr;

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        LOG("Error: BIO_new for base64 failed");
        return NULL;
    }
    LOG("BIO for base64 created");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        LOG("Error: BIO_new for memory buffer failed");
        BIO_free(b64);
        return NULL;
    }
    LOG("BIO for memory buffer created");

    // 不使用换行符
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    LOG("Base64 no newline flag set and BIOs pushed");

    if (BIO_write(bio, buffer, length) <= 0) {
        LOG("Error: BIO_write failed");
        BIO_free_all(bio);
        return NULL;
    }
    LOG("Data written to BIO");

    if (BIO_flush(bio) != 1) {
        LOG("Error: BIO_flush failed");
        BIO_free_all(bio);
        return NULL;
    }
    LOG("BIO flushed successfully");

    BIO_get_mem_ptr(bio, &buffer_ptr);
    if (!buffer_ptr) {
        LOG("Error: BIO_get_mem_ptr failed");
        BIO_free_all(bio);
        return NULL;
    }
    LOG("Memory pointer obtained from BIO");

    char *b64_text = (char*)malloc(buffer_ptr->length + 1);
    if (!b64_text) {
        LOG("Error: Memory allocation for b64_text failed");
        BIO_free_all(bio);
        return NULL;
    }
    LOG("Memory allocated for Base64 encoded text");

    memcpy(b64_text, buffer_ptr->data, buffer_ptr->length);
    b64_text[buffer_ptr->length] = '\0';
    LOG("Base64 encoding completed");

    BIO_free_all(bio);
    LOG("BIOs freed");

    LOG("Exiting base64_encode successfully");
    return b64_text;
}

// Base64解码
unsigned char* base64_decode(const char* b64_message, size_t* out_len) {
    LOG("Entering base64_decode");

    int decode_len = strlen(b64_message);
    LOG("Base64 message length: %d", decode_len);
    unsigned char *buffer = (unsigned char*)malloc(decode_len);
    if (!buffer) {
        LOG("Error: Memory allocation for decode buffer failed");
        return NULL;
    }
    LOG("Memory allocated for decode buffer");

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        LOG("Error: BIO_new for base64 failed");
        free(buffer);
        return NULL;
    }
    LOG("BIO for base64 created");

    BIO *bio = BIO_new_mem_buf(b64_message, -1);
    if (!bio) {
        LOG("Error: BIO_new_mem_buf failed");
        BIO_free(b64);
        free(buffer);
        return NULL;
    }
    LOG("Memory BIO created for Base64 message");

    // 不使用换行符
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    LOG("Base64 no newline flag set and BIOs pushed");

    int decoded_len = BIO_read(bio, buffer, decode_len);
    if (decoded_len <= 0) {
        LOG("Error: BIO_read failed with decoded_len: %d", decoded_len);
        BIO_free_all(bio);
        free(buffer);
        return NULL;
    }
    LOG("BIO_read successful, decoded length: %d", decoded_len);

    *out_len = decoded_len;
    LOG("Output length set to: %zu", *out_len);

    BIO_free_all(bio);
    LOG("BIOs freed");

    LOG("Exiting base64_decode successfully");
    return buffer;
}

// AES-256-CBC 加密
int aes256_encrypt(const unsigned char *plaintext, int plaintext_len,
                  const unsigned char *key,
                  const unsigned char *iv,
                  unsigned char *ciphertext) {
    LOG("Entering aes256_encrypt");

    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    // 创建并初始化上下文
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        LOG("Error: EVP_CIPHER_CTX_new failed");
        return SC_ERR_ENCRYPT;
    }
    LOG("EVP_CIPHER_CTX created");

    // 初始化加密操作
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        LOG("Error: EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_ENCRYPT;
    }
    LOG("EVP_EncryptInit_ex initialized");

    // 提供明文并获取密文
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        LOG("Error: EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_ENCRYPT;
    }
    LOG("EVP_EncryptUpdate successful, len: %d", len);
    int ciphertext_len = len;

    // 完成加密
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        LOG("Error: EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_ENCRYPT;
    }
    ciphertext_len += len;
    LOG("EVP_EncryptFinal_ex successful, ciphertext_len: %d", ciphertext_len);

    // 清理
    EVP_CIPHER_CTX_free(ctx);
    LOG("EVP_CIPHER_CTX freed");

    LOG("Exiting aes256_encrypt with ciphertext_len: %d", ciphertext_len);
    return ciphertext_len;
}

// AES-256-CBC 解密
int aes256_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                  const unsigned char *key,
                  const unsigned char *iv,
                  unsigned char *plaintext) {
    LOG("Entering aes256_decrypt");

    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    // 创建并初始化上下文
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        LOG("Error: EVP_CIPHER_CTX_new failed");
        return SC_ERR_DECRYPT;
    }
    LOG("EVP_CIPHER_CTX created");

    // 初始化解密操作
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        LOG("Error: EVP_DecryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_DECRYPT;
    }
    LOG("EVP_DecryptInit_ex initialized");

    // 提供密文并获取明文
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        LOG("Error: EVP_DecryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_DECRYPT;
    }
    LOG("EVP_DecryptUpdate successful, len: %d", len);
    int plaintext_len = len;

    // 完成解密
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        LOG("Error: EVP_DecryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_DECRYPT;
    }
    plaintext_len += len;
    LOG("EVP_DecryptFinal_ex successful, plaintext_len: %d", plaintext_len);

    // 清理
    EVP_CIPHER_CTX_free(ctx);
    LOG("EVP_CIPHER_CTX freed");

    LOG("Exiting aes256_decrypt with plaintext_len: %d", plaintext_len);
    return plaintext_len;
}

// 加密字符串
int encrypt_string(const char *plaintext, const char *password, char **ciphertext_out) {
    LOG("Entering encrypt_string");

    if (!plaintext || !password || !ciphertext_out) {
        LOG("Error: Invalid input parameters");
        return SC_ERR_ENCRYPT;
    }
    LOG("Input parameters are valid");

    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned char iv[16]; // AES块大小为16字节

    // 生成密钥
    if (generate_aes256_key(password, key) != SC_SUCCESS) {
        LOG("Error: generate_aes256_key failed");
        return SC_ERR_KEY_GEN;
    }
    LOG("AES-256 key generated successfully");

    // 生成随机IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        LOG("Error: RAND_bytes for IV failed");
        return SC_ERR_ENCRYPT;
    }
    LOG("Random IV generated");

    // 加密
    int plaintext_len = strlen(plaintext);
    LOG("Plaintext length: %d", plaintext_len);
    int ciphertext_len = plaintext_len + 16; // 最大可能长度
    unsigned char *ciphertext = (unsigned char*)malloc(ciphertext_len);
    if (!ciphertext) {
        LOG("Error: Memory allocation for ciphertext failed");
        return SC_ERR_MEMORY;
    }
    LOG("Memory allocated for ciphertext");

    int len = aes256_encrypt((unsigned char*)plaintext, plaintext_len, key, iv, ciphertext);
    if (len < 0) {
        LOG("Error: aes256_encrypt failed with len: %d", len);
        free(ciphertext);
        return SC_ERR_ENCRYPT;
    }
    ciphertext_len = len;
    LOG("Encryption successful, ciphertext_len: %d", ciphertext_len);

    // 将IV和密文拼接
    size_t total_len = sizeof(iv) + ciphertext_len;
    LOG("Total length for IV and ciphertext: %zu", total_len);
    unsigned char *iv_ciphertext = (unsigned char*)malloc(total_len);
    if (!iv_ciphertext) {
        LOG("Error: Memory allocation for iv_ciphertext failed");
        free(ciphertext);
        return SC_ERR_MEMORY;
    }
    LOG("Memory allocated for iv_ciphertext");

    memcpy(iv_ciphertext, iv, sizeof(iv));
    memcpy(iv_ciphertext + sizeof(iv), ciphertext, ciphertext_len);
    LOG("IV and ciphertext concatenated");

    // Base64编码
    char *b64_encoded = base64_encode(iv_ciphertext, total_len);
    if (!b64_encoded) {
        LOG("Error: base64_encode failed");
        free(ciphertext);
        free(iv_ciphertext);
        return SC_ERR_BASE64;
    }
    LOG("Base64 encoding successful");

    *ciphertext_out = b64_encoded;
    LOG("Ciphertext output set");

    // 清理
    free(ciphertext);
    free(iv_ciphertext);
    LOG("Ciphertext and iv_ciphertext memory freed");

    LOG("Exiting encrypt_string with success");
    return SC_SUCCESS;
}

// 解密字符串
int decrypt_string(const char *ciphertext, const char *password, char **plaintext_out) {
    LOG("Entering decrypt_string");

    if (!ciphertext || !password || !plaintext_out) {
        LOG("Error: Invalid input parameters");
        return SC_ERR_DECRYPT;
    }
    LOG("Input parameters are valid");

    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned char iv[16]; // AES块大小为16字节

    // 生成密钥
    if (generate_aes256_key(password, key) != SC_SUCCESS) {
        LOG("Error: generate_aes256_key failed");
        return SC_ERR_KEY_GEN;
    }
    LOG("AES-256 key generated successfully");

    // Base64解码
    size_t decoded_len;
    LOG("Decoding Base64 ciphertext");
    unsigned char *iv_ciphertext = base64_decode(ciphertext, &decoded_len);
    if (!iv_ciphertext) {
        LOG("Error: base64_decode failed");
        return SC_ERR_BASE64;
    }
    LOG("Base64 decoding successful, decoded_len: %zu", decoded_len);

    if (decoded_len < sizeof(iv)) {
        LOG("Error: Decoded data length (%zu) is less than IV size (%zu)", decoded_len, sizeof(iv));
        free(iv_ciphertext);
        return SC_ERR_DECRYPT;
    }
    LOG("Decoded data length is sufficient");

    // 分离IV和密文
    memcpy(iv, iv_ciphertext, sizeof(iv));
    LOG("IV extracted from decoded data");
    unsigned char *ciphertext_bin = iv_ciphertext + sizeof(iv);
    int ciphertext_len = decoded_len - sizeof(iv);
    LOG("Ciphertext length after extracting IV: %d", ciphertext_len);

    // 解密
    unsigned char *plaintext = (unsigned char*)malloc(ciphertext_len); // 明文长度 <= 密文长度
    if (!plaintext) {
        LOG("Error: Memory allocation for plaintext failed");
        free(iv_ciphertext);
        return SC_ERR_MEMORY;
    }
    LOG("Memory allocated for plaintext");

    int len = aes256_decrypt(ciphertext_bin, ciphertext_len, key, iv, plaintext);
    if (len < 0) {
        LOG("Error: aes256_decrypt failed with len: %d", len);
        free(iv_ciphertext);
        free(plaintext);
        return SC_ERR_DECRYPT;
    }
    int plaintext_len = len;
    LOG("Decryption successful, plaintext_len: %d", plaintext_len);

    // 确保字符串以NULL结尾
    char *plaintext_str = (char*)malloc(plaintext_len + 1);
    if (!plaintext_str) {
        LOG("Error: Memory allocation for plaintext_str failed");
        free(iv_ciphertext);
        free(plaintext);
        return SC_ERR_MEMORY;
    }
    LOG("Memory allocated for plaintext_str");

    memcpy(plaintext_str, plaintext, plaintext_len);
    plaintext_str[plaintext_len] = '\0';
    LOG("Plaintext string null-terminated");

    *plaintext_out = plaintext_str;
    LOG("Plaintext output set");

    // 清理
    free(iv_ciphertext);
    free(plaintext);
    LOG("iv_ciphertext and plaintext memory freed");

    LOG("Exiting decrypt_string with success");
    return SC_SUCCESS;
}
