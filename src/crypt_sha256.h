#ifndef CRYPT_SHA256_H
#define CRYPT_SHA256_H

#ifdef __cplusplus
extern "C" {
#endif

char* php_sha256_crypt(const char *key, const char *salt);

#ifdef __cplusplus
}
#endif

#endif // CRYPT_SHA256_H
