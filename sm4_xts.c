#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void print_hex(const unsigned char *data, int length, const char *label) {
    printf("%s: ", label);
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void hex_to_bin(const char *hex, unsigned char *bin, int bin_size) {
    for (int i = 0; i < bin_size; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }
}

void hex_to_ascii(const char *hex, unsigned char *ascii, int ascii_len) {
    for (int i = 0; i < ascii_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &ascii[i]);
    }
}

void ascii_to_hex(const unsigned char *ascii, char *hex, int ascii_len) {
    for (int i = 0; i < ascii_len; i++) {
        sprintf(hex + 2 * i, "%02x", ascii[i]);
    }
}

int encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    const EVP_CIPHER *cipher;

    /* Fetch the cipher implementation */
    cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher)
        handleErrors();

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free((EVP_CIPHER *)cipher); // Cast away 'const' when freeing

    return ciphertext_len;
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    const EVP_CIPHER *cipher;

    /* Fetch the cipher implementation */
    cipher = EVP_CIPHER_fetch(NULL, "SM4-XTS", NULL);
    if (!cipher)
        handleErrors();

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
        handleErrors();

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free((EVP_CIPHER *)cipher); // Cast away 'const' when freeing

    return plaintext_len;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <-e|-d> <SM4_key> <IV> <input_text_or_ciphertext>\n", argv[0]);
        return 1;
    }

    /* Extract command-line arguments */
    const char *operation = argv[1];
    unsigned char binary_key[32]; // 256-bit key for SM4-XTS (two 128-bit keys)
    unsigned char binary_iv[16];  // 128-bit IV

    // Convert hex key and IV to binary
    hex_to_bin(argv[2], binary_key, sizeof(binary_key)); // Ensure argv[2] has 64 hex characters
    hex_to_bin(argv[3], binary_iv, sizeof(binary_iv));   // Ensure argv[3] has 32 hex characters

    // Print the binary SM4 key and IV for verification
    print_hex(binary_key, sizeof(binary_key), "SM4 Key (binary)");
    print_hex(binary_iv, sizeof(binary_iv), "IV (binary)");

    const char *input_data = argv[4];

    /* Initialize the library */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    if (strcmp(operation, "-e") == 0) {
        /* Handle encryption */
        int input_len = strlen(input_data) / 2;  // Assuming hex input
        unsigned char *ascii_input = malloc(input_len);
        if (ascii_input == NULL) {
            fprintf(stderr, "Memory allocation error.\n");
            return 1;
        }
        hex_to_ascii(input_data, ascii_input, input_len);

        // Print the plaintext in binary form
        print_hex(ascii_input, input_len, "Plaintext (binary)");

        unsigned char *output_data = malloc(input_len + EVP_MAX_BLOCK_LENGTH);
        if (output_data == NULL) {
            fprintf(stderr, "Memory allocation error.\n");
            free(ascii_input);
            return 1;
        }

        int ciphertext_len = encrypt(ascii_input, input_len, binary_key, binary_iv, output_data);

        char *hex_output = malloc(2 * ciphertext_len + 1);
        if (hex_output == NULL) {
            fprintf(stderr, "Memory allocation error.\n");
            free(ascii_input);
            free(output_data);
            return 1;
        }
        ascii_to_hex(output_data, hex_output, ciphertext_len);
        printf("Ciphertext (hex): %s\n", hex_output);

        free(ascii_input);
        free(output_data);
        free(hex_output);
    } else if (strcmp(operation, "-d") == 0) {
        /* Handle decryption */
        int input_len = strlen(input_data);
        int binary_len = input_len / 2;
        unsigned char *binary_input = malloc(binary_len);
        unsigned char *output_data = malloc(binary_len + EVP_MAX_BLOCK_LENGTH);
        if (binary_input == NULL || output_data == NULL) {
            fprintf(stderr, "Memory allocation error.\n");
            free(binary_input);
            free(output_data);
            return 1;
        }

        hex_to_ascii(input_data, binary_input, binary_len);
        int plaintext_len = decrypt(binary_input, binary_len, binary_key, binary_iv, output_data);
        output_data[plaintext_len] = '\0'; // Null-terminate the decrypted string
        printf("Decrypted Text: %s\n", output_data);

        free(binary_input);
        free(output_data);
    } else {
        fprintf(stderr, "Invalid operation: Use -e for encryption or -d for decryption.\n");
        return 1;
    }

    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
