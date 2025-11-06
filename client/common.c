#include "common.h"
#include <stdlib.h>
#include <sodium.h>
#include <unistd.h>

/**
 * @brief Write binary data to a file.
 * @param path Path to the file.
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 * @return 0 on success, -1 on failure.
 */
int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen failed");
        return -1;
    }
    if (fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "fwrite failed\n");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}


/**
 * @brief Read binary data from a file.
 * @param path Path to the file.
 * @param data Pointer to the buffer to store the binary data.
 * @param len Length of the binary data to read.
 * @return 0 on success, -1 on failure.
 */
int read_file(const char *path, unsigned char *data, size_t len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen failed"); 
        return -1;
    }
    if (fread(data, 1, len, f) != len) {
        if (len > 0) {
            fprintf(stderr, "fread failed (expected %zu bytes)\n", len);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}


/**
 * @brief Check if a file exists.
 * @param filename Path to the file.
 * @return 1 if the file exists, 0 otherwise.
 */
int file_exists(const char *filename) {
    return access(filename, F_OK) == 0;
}


/**
 * @brief Read a line of input from stdin.
 * @return Pointer to the allocated string, or NULL on failure.
 */
char *read_message_from_stdin() {
    printf("Enter message: ");
    fflush(stdout);
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read = getline(&line, &len, stdin);
    if (read == -1) {
        free(line);
        return NULL;
    }
    if (read > 0 && line[read - 1] == '\n') {
        line[read - 1] = '\0'; // Remove newline
    }
    return line;
}


/**
 * @brief Encode binary data to a Base64 string.
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 * @return NULL on failure, otherwise pointer to allocated Base64 string.
 */
char *b64_encode(const unsigned char *data, size_t len) {
    // Calculate buffer size needed
    size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *b64_buf = malloc(b64_len);
    if (!b64_buf) {
        fprintf(stderr, "malloc failed for b64_encode\n");
        return NULL;
    }

    // Encode
    sodium_bin2base64(b64_buf, b64_len, data, len, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return b64_buf;
}


/**
 * @brief Decode a Base64 string to binary data.
 * @param b64_str Pointer to the Base64 string.
 * @param data Pointer to the buffer to store the binary data.
 * @param data_len Length of the binary data buffer.
 * @return Number of bytes decoded, or 0 on failure.
 */
size_t b64_decode(const char *b64_str, unsigned char *data, size_t data_len) {
    size_t decoded_len = 0;
    if (sodium_base642bin(data, data_len, b64_str, strlen(b64_str),
                          NULL, &decoded_len, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        fprintf(stderr, "sodium_base642bin failed\n");
        return 0;
    }
    return decoded_len;
}


/**
 * @brief Decode a Base64 string to binary data, allocating exact buffer.
 * @param b64_input Pointer to the Base64 string.
 * @param b64_len Length of the Base64 string. If 0, strlen() will be used.
 * @param out_len Pointer to size_t to store length of decoded data.
 * @return NULL on failure, otherwise pointer to allocated binary data.
 */
unsigned char *b64_decode_ex(const char *b64_input, size_t b64_len, size_t *out_len) {
    if (b64_input == NULL) {
        fprintf(stderr, "b64_decode_ex: FATAL: b64_input was NULL.\n");
        return NULL;
    }
    
    if (b64_len == 0) {
        b64_len = strlen(b64_input);
    }

    if (b64_len == 0) {
        *out_len = 0;
        unsigned char *output = malloc(1);
        if (output) output[0] = '\0';
        return output;
    }

    const char *ignore_chars = NULL;
    
    // 1. Allocate a temporary buffer. A buffer the same size as the input
    size_t temp_buf_len = b64_len;
    unsigned char *temp_output = malloc(temp_buf_len);
    if (!temp_output) {
        fprintf(stderr, "b64_decode_ex: malloc failed for temp buffer\n");
        return NULL;
    }

    // 2. Do the actual decoding into the temporary buffer
    size_t bin_len_actual;
    if (sodium_base642bin(temp_output, temp_buf_len,
                          b64_input, b64_len,
                          ignore_chars, &bin_len_actual,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        fprintf(stderr, "b64_decode_ex: sodium_base642bin failed. Invalid base64 string?\n");
        free(temp_output);
        return NULL;
    }

    // 3. Allocate the final buffer of the exact size
    unsigned char *output = malloc(bin_len_actual);
    if (!output) {
        fprintf(stderr, "b64_decode_ex: malloc failed for final buffer\n");
        free(temp_output);
        return NULL;
    }

    // 4. Copy from temp to final buffer
    memcpy(output, temp_output, bin_len_actual);
    free(temp_output);
    *out_len = bin_len_actual;
    return output;
}


/**
 * @brief HKDF key derivation function (RFC 5869) using SHA-512.
 * @param okm Pointer to output keying material buffer.
 * @param okm_len Length of the output keying material.
 * @param ikm Pointer to input keying material buffer.
 * @param ikm_len Length of the input keying material.
 * @param info Contextual information string.
 * @return 0 on success, -1 on failure.
 */
int hkdf(unsigned char *okm, size_t okm_len,
         const unsigned char *ikm, size_t ikm_len,
         const char *info) {

    unsigned char prk[crypto_kdf_hkdf_sha512_KEYBYTES];

    // 1. HKDF-Extract: prk = HMAC-Hash(salt, ikm)
    if (crypto_kdf_hkdf_sha512_extract(prk, // out: Pseudo-Random Key
                                     NULL, 0, // salt, salt_len
                                     ikm, ikm_len) != 0) {
        fprintf(stderr, "HKDF Extract failed\n");
        return -1;
    }

    // 2. HKDF-Expand: okm = HMAC-Hash(prk, info || 0x01)
    // Check output length constraints
    if (okm_len > crypto_kdf_hkdf_sha512_bytes_max()) {
        fprintf(stderr, "HKDF Error: OKM length > %zu not supported.\n",
                crypto_kdf_hkdf_sha512_bytes_max());
        sodium_memzero(prk, sizeof(prk));
        return -1;
    }

    if (crypto_kdf_hkdf_sha512_expand(okm, okm_len,
                                    (const unsigned char *)info, strlen(info),
                                    prk) != 0) {
        fprintf(stderr, "HKDF Expand failed\n");
        sodium_memzero(prk, sizeof(prk));
        return -1;
    }

    // 3. Clean up the sensitive intermediate key
    sodium_memzero(prk, sizeof(prk));

    return 0;
}


/** 
 * @brief Print data in hex format.
 * @param label Label to print before the hex data.
 * @param data Pointer to the binary data.
 * @param len Length of the binary data.
 */
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}