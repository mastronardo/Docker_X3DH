#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <xeddsa.h>

// X3DH Info Parameter
#define X3DH_INFO_STRING "MyProtocol"

int write_file(const char *path, const unsigned char *data, size_t len);
int read_file(const char *path, unsigned char *data, size_t len);
int file_exists(const char *filename);

char *read_message_from_stdin();

char *b64_encode(const unsigned char *data, size_t len);
size_t b64_decode(const char *b64_str, unsigned char *data, size_t data_len);
unsigned char *b64_decode_ex(const char *b64_input, size_t b64_len, size_t *out_len);

int hkdf(unsigned char *okm, size_t okm_len,
         const unsigned char *ikm, size_t ikm_len,
         const char *info);

void print_hex(const char *label, const unsigned char *data, size_t len);

#endif // COMMON_H