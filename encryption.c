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

// 从密码生成AES-256密钥
int generate_aes256_key(const char *password, unsigned char *key_out) {
    if (!password || !key_out) {
        return SC_ERR_KEY_GEN;
    }
    // 使用SHA-256哈希密码
    if (!SHA256((unsigned char*)password, strlen(password), key_out)) {
        return SC_ERR_KEY_GEN;
    }
    return SC_SUCCESS;
}

// Base64编码
char* base64_encode(const unsigned char* buffer, size_t length) {
    BUF_MEM *buffer_ptr;

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) return NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        BIO_free(b64);
        return NULL;
    }

    // 不使用换行符
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    if (BIO_write(bio, buffer, length) <= 0) {
        BIO_free_all(bio);
        return NULL;
    }

    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        return NULL;
    }

    BIO_get_mem_ptr(bio, &buffer_ptr);
    if (!buffer_ptr) {
        BIO_free_all(bio);
        return NULL;
    }

    char *b64_text = (char*)malloc(buffer_ptr->length + 1);
    if (!b64_text) {
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(b64_text, buffer_ptr->data, buffer_ptr->length);
    b64_text[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return b64_text;
}

// Base64解码
unsigned char* base64_decode(const char* b64_message, size_t* out_len) {
    int decode_len = strlen(b64_message);
    unsigned char *buffer = (unsigned char*)malloc(decode_len);
    if (!buffer) return NULL;

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        free(buffer);
        return NULL;
    }

    BIO *bio = BIO_new_mem_buf(b64_message, -1);
    if (!bio) {
        BIO_free(b64);
        free(buffer);
        return NULL;
    }

    // 不使用换行符
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    int decoded_len = BIO_read(bio, buffer, decode_len);
    if (decoded_len <= 0) {
        BIO_free_all(bio);
        free(buffer);
        return NULL;
    }

    *out_len = decoded_len;
    BIO_free_all(bio);
    return buffer;
}

// AES-256-CBC 加密
int aes256_encrypt(const unsigned char *plaintext, int plaintext_len,
                  const unsigned char *key,
                  const unsigned char *iv,
                  unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    // 创建并初始化上下文
    if(!((ctx = EVP_CIPHER_CTX_new()))) {
        return SC_ERR_ENCRYPT;
    }

    // 初始化加密操作
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_ENCRYPT;
    }

    // 提供明文并获取密文
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_ENCRYPT;
    }
    int ciphertext_len = len;

    // 完成加密
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_ENCRYPT;
    }
    ciphertext_len += len;

    // 清理
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES-256-CBC 解密
int aes256_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                  const unsigned char *key,
                  const unsigned char *iv,
                  unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    // 创建并初始化上下文
    if(!((ctx = EVP_CIPHER_CTX_new()))) {
        return SC_ERR_DECRYPT;
    }

    // 初始化解密操作
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_DECRYPT;
    }

    // 提供密文并获取明文
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_DECRYPT;
    }
    int plaintext_len = len;

    // 完成解密
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return SC_ERR_DECRYPT;
    }
    plaintext_len += len;

    // 清理
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// 加密字符串
int encrypt_string(const char *plaintext, const char *password, char **ciphertext_out) {
    if (!plaintext || !password || !ciphertext_out) {
        return SC_ERR_ENCRYPT;
    }

    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned char iv[16]; // AES块大小为16字节

    // 生成密钥
    if (generate_aes256_key(password, key) != SC_SUCCESS) {
        return SC_ERR_KEY_GEN;
    }

    // 生成随机IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        return SC_ERR_ENCRYPT;
    }

    // 加密
    int plaintext_len = strlen(plaintext);
    int ciphertext_len = plaintext_len + 16; // 最大可能长度
    unsigned char *ciphertext = (unsigned char*)malloc(ciphertext_len);
    if (!ciphertext) {
        return SC_ERR_MEMORY;
    }

    int len = aes256_encrypt((unsigned char*)plaintext, plaintext_len, key, iv, ciphertext);
    if (len < 0) {
        free(ciphertext);
        return SC_ERR_ENCRYPT;
    }
    ciphertext_len = len;

    // 将IV和密文拼接
    size_t total_len = sizeof(iv) + ciphertext_len;
    unsigned char *iv_ciphertext = (unsigned char*)malloc(total_len);
    if (!iv_ciphertext) {
        free(ciphertext);
        return SC_ERR_MEMORY;
    }
    memcpy(iv_ciphertext, iv, sizeof(iv));
    memcpy(iv_ciphertext + sizeof(iv), ciphertext, ciphertext_len);

    // Base64编码
    char *b64_encoded = base64_encode(iv_ciphertext, total_len);
    if (!b64_encoded) {
        free(ciphertext);
        free(iv_ciphertext);
        return SC_ERR_BASE64;
    }

    *ciphertext_out = b64_encoded;

    // 清理
    free(ciphertext);
    free(iv_ciphertext);

    return SC_SUCCESS;
}

// 解密字符串
int decrypt_string(const char *ciphertext, const char *password, char **plaintext_out) {
    if (!ciphertext || !password || !plaintext_out) {
        return SC_ERR_DECRYPT;
    }

    unsigned char key[SHA256_DIGEST_LENGTH];
    unsigned char iv[16]; // AES块大小为16字节

    // 生成密钥
    if (generate_aes256_key(password, key) != SC_SUCCESS) {
        return SC_ERR_KEY_GEN;
    }

    // Base64解码
    size_t decoded_len;
    unsigned char *iv_ciphertext = base64_decode(ciphertext, &decoded_len);
    if (!iv_ciphertext) {
        return SC_ERR_BASE64;
    }

    if (decoded_len < sizeof(iv)) {
        free(iv_ciphertext);
        return SC_ERR_DECRYPT;
    }

    // 分离IV和密文
    memcpy(iv, iv_ciphertext, sizeof(iv));
    unsigned char *ciphertext_bin = iv_ciphertext + sizeof(iv);
    int ciphertext_len = decoded_len - sizeof(iv);

    // 解密
    unsigned char *plaintext = (unsigned char*)malloc(ciphertext_len); // 明文长度 <= 密文长度
    if (!plaintext) {
        free(iv_ciphertext);
        return SC_ERR_MEMORY;
    }

    int len = aes256_decrypt(ciphertext_bin, ciphertext_len, key, iv, plaintext);
    if (len < 0) {
        free(iv_ciphertext);
        free(plaintext);
        return SC_ERR_DECRYPT;
    }
    int plaintext_len = len;

    // 确保字符串以NULL结尾
    char *plaintext_str = (char*)malloc(plaintext_len + 1);
    if (!plaintext_str) {
        free(iv_ciphertext);
        free(plaintext);
        return SC_ERR_MEMORY;
    }
    memcpy(plaintext_str, plaintext, plaintext_len);
    plaintext_str[plaintext_len] = '\0';

    *plaintext_out = plaintext_str;

    // 清理
    free(iv_ciphertext);
    free(plaintext);

    return SC_SUCCESS;
}
