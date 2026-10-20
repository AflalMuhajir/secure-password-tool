/* main.c - Secure Password Generator + Analyzer + AES-256-CBC
 * Requires: aes.h + aes.c (with AES256 enabled)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

#define AES256 1
#define CBC 1
#include "aes.h"

#define MAX_PASS_LEN     128
#define MIN_PASS_LEN     8
#define MAX_INPUT        512
#define AES_BLOCKLEN     16
#define AES_KEYLEN       32

/* Character sets */
static const char *LOWER   = "abcdefghijklmnopqrstuvwxyz";
static const char *UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *DIGITS  = "0123456789";
static const char *SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?/";
static const char *AMBIGUOUS = "0O1lI";

/* ========== Secure Random ========== */
int secure_random_bytes(unsigned char *buf, size_t len) {
#ifdef _WIN32
    return (BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) { close(fd); return -1; }
        total += n;
    }
    close(fd);
    return 0;
#endif
}

unsigned int secure_random_uint(unsigned int max) {
    unsigned char bytes[4];
    unsigned int val;
    if (secure_random_bytes(bytes, 4) != 0)
        val = (unsigned int)rand();
    else
        val = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    return val % max;
}

/* ========== Password Generator ========== */
int generate_password(char *out, int length,
                      int use_lower, int use_upper,
                      int use_digits, int use_symbols,
                      int exclude_ambiguous)
{
    if (length < MIN_PASS_LEN || length > MAX_PASS_LEN) return -1;

    char charset[256] = {0};
    size_t charset_len = 0;

    if (use_lower)  for (const char *p = LOWER;  *p; p++) if (!exclude_ambiguous || !strchr(AMBIGUOUS, *p)) charset[charset_len++] = *p;
    if (use_upper)  for (const char *p = UPPER;  *p; p++) if (!exclude_ambiguous || !strchr(AMBIGUOUS, *p)) charset[charset_len++] = *p;
    if (use_digits) for (const char *p = DIGITS; *p; p++) if (!exclude_ambiguous || !strchr(AMBIGUOUS, *p)) charset[charset_len++] = *p;
    if (use_symbols) for (const char *p = SYMBOLS; *p; p++) charset[charset_len++] = *p;

    if (charset_len == 0) return -1;

    int pos = 0;
    if (use_lower)  { char c; do { c = LOWER[secure_random_uint(26)]; } while (exclude_ambiguous && strchr(AMBIGUOUS, c)); out[pos++] = c; }
    if (use_upper)  { char c; do { c = UPPER[secure_random_uint(26)]; } while (exclude_ambiguous && strchr(AMBIGUOUS, c)); out[pos++] = c; }
    if (use_digits) { char c; do { c = DIGITS[secure_random_uint(10)]; } while (exclude_ambiguous && strchr(AMBIGUOUS, c)); out[pos++] = c; }
    if (use_symbols) out[pos++] = SYMBOLS[secure_random_uint((unsigned)strlen(SYMBOLS))];

    for (; pos < length; pos++)
        out[pos] = charset[secure_random_uint((unsigned)charset_len)];

    for (int i = length - 1; i > 0; i--) {
        int j = secure_random_uint(i + 1);
        char tmp = out[i]; out[i] = out[j]; out[j] = tmp;
    }
    out[length] = '\0';
    return 0;
}

/* ========== Analyzer ========== */
typedef struct {
    int length, has_lower, has_upper, has_digit, has_symbol;
    int has_sequential, has_repeated;
    double entropy;
    const char *rating;
} AnalysisResult;

void analyze_password(const char *password, AnalysisResult *res) {
    memset(res, 0, sizeof(*res));
    res->length = (int)strlen(password);
    int charset_size = 0;

    for (const char *p = password; *p; p++) {
        if (islower((unsigned char)*p)) res->has_lower = 1;
        else if (isupper((unsigned char)*p)) res->has_upper = 1;
        else if (isdigit((unsigned char)*p)) res->has_digit = 1;
        else res->has_symbol = 1;
    }
    if (res->has_lower)  charset_size += 26;
    if (res->has_upper)  charset_size += 26;
    if (res->has_digit)  charset_size += 10;
    if (res->has_symbol) charset_size += 32;

    if (charset_size > 0)
        res->entropy = res->length * log2((double)charset_size);

    for (int i = 0; i < res->length - 2; i++) {
        if (password[i+1] == password[i]+1 && password[i+2] == password[i]+2)
            res->has_sequential = 1;
        if (password[i] == password[i+1] && password[i] == password[i+2])
            res->has_repeated = 1;
    }

    if (res->length < 8 || res->entropy < 28) res->rating = "Very Weak";
    else if (res->length < 10 || res->entropy < 36 || !(res->has_lower && res->has_upper && res->has_digit))
        res->rating = "Weak";
    else if (res->entropy < 60 || !res->has_symbol) res->rating = "Medium";
    else if (res->entropy < 80) res->rating = "Strong";
    else res->rating = "Very Strong";
}

void print_analysis(const AnalysisResult *res, const char *password) {
    printf("\n========== Password Analysis ==========\n");
    printf("Password : %s\n", password);
    printf("Length   : %d\n", res->length);
    printf("Entropy  : ~%.1f bits\n", res->entropy);
    printf("Strength : %s\n", res->rating);
    if (res->has_sequential) printf("Warning  : Sequential characters\n");
    if (res->has_repeated)   printf("Warning  : Repeated characters\n");
    printf("=======================================\n\n");
}

/* ========== AES-256-CBC Helpers ========== */
void derive_key(const char *passphrase, uint8_t key[AES_KEYLEN]) {
    size_t len = strlen(passphrase);
    memset(key, 0, AES_KEYLEN);
    memcpy(key, passphrase, len > AES_KEYLEN ? AES_KEYLEN : len);
    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < AES_KEYLEN; j++)
            key[j] ^= passphrase[j % len] + (uint8_t)i;
    }
}

size_t pkcs7_pad(uint8_t *buf, size_t len, size_t max_len) {
    size_t pad = AES_BLOCKLEN - (len % AES_BLOCKLEN);
    if (len + pad > max_len) return 0;
    for (size_t i = 0; i < pad; i++)
        buf[len + i] = (uint8_t)pad;
    return len + pad;
}

int pkcs7_unpad(uint8_t *buf, size_t len) {
    if (len == 0 || len % AES_BLOCKLEN != 0) return -1;
    uint8_t pad = buf[len - 1];
    if (pad == 0 || pad > AES_BLOCKLEN) return -1;
    for (size_t i = 0; i < pad; i++)
        if (buf[len - 1 - i] != pad) return -1;
    return (int)(len - pad);
}

void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i*2, "%02x", in[i]);
    out[len*2] = '\0';
}

int hex_to_bytes(const char *hex, uint8_t *out, size_t max_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0 || len/2 > max_len) return -1;
    for (size_t i = 0; i < len/2; i++) {
        unsigned int byte;
        if (sscanf(hex + i*2, "%02x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return (int)(len/2);
}

int aes256_encrypt(const char *plaintext, const char *passphrase,
                   char *hex_out, size_t hex_out_size)
{
    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_BLOCKLEN];
    uint8_t buf[MAX_INPUT + AES_BLOCKLEN];
    size_t len = strlen(plaintext);

    if (len > MAX_INPUT - AES_BLOCKLEN) return -1;

    derive_key(passphrase, key);
    if (secure_random_bytes(iv, AES_BLOCKLEN) != 0) return -1;

    memcpy(buf, plaintext, len);
    size_t padded_len = pkcs7_pad(buf, len, sizeof(buf));
    if (padded_len == 0) return -1;

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, buf, padded_len);

    if (2 * (AES_BLOCKLEN + padded_len) + 1 > hex_out_size) return -1;

    bytes_to_hex(iv, AES_BLOCKLEN, hex_out);
    bytes_to_hex(buf, padded_len, hex_out + 32);

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(buf, 0, sizeof(buf));
    return 0;
}

int aes256_decrypt(const char *hex_in, const char *passphrase,
                   char *plaintext_out, size_t out_size)
{
    uint8_t key[AES_KEYLEN];
    uint8_t data[MAX_INPUT];
    int data_len = hex_to_bytes(hex_in, data, sizeof(data));
    if (data_len < AES_BLOCKLEN + AES_BLOCKLEN || data_len % AES_BLOCKLEN != 0)
        return -1;

    derive_key(passphrase, key);

    uint8_t *iv = data;
    uint8_t *ciphertext = data + AES_BLOCKLEN;
    size_t ct_len = data_len - AES_BLOCKLEN;

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, ciphertext, ct_len);

    int plain_len = pkcs7_unpad(ciphertext, ct_len);
    if (plain_len < 0 || (size_t)plain_len >= out_size) {
        memset(key, 0, sizeof(key));
        return -1;
    }

    memcpy(plaintext_out, ciphertext, plain_len);
    plaintext_out[plain_len] = '\0';

    memset(key, 0, sizeof(key));
    memset(data, 0, sizeof(data));
    return 0;
}

/* ========== Menu ========== */
void clear_input(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int main(void) {
    char password[MAX_PASS_LEN + 1];
    char input[MAX_INPUT];
    char hex_buf[MAX_INPUT * 2];
    char decrypted[MAX_INPUT];
    int choice;
    AnalysisResult analysis;

    srand((unsigned)time(NULL));

    printf("================================================\n");
    printf("  Secure Password Tool + AES-256-CBC\n");
    printf("  Generator | Analyzer | Encrypt | Decrypt\n");
    printf("================================================\n");

    while (1) {
        printf("\n1. Generate Password\n");
        printf("2. Analyze Password\n");
        printf("3. Generate + Analyze\n");
        printf("4. Encrypt a Password/String (AES-256)\n");
        printf("5. Decrypt (AES-256)\n");
        printf("6. Exit\n");
        printf("Choice: ");

        if (scanf("%d", &choice) != 1) {
            clear_input();
            continue;
        }
        clear_input();

        if (choice == 6) break;

        if (choice == 1 || choice == 3) {
            int length = 16, use_lower=1, use_upper=1, use_digits=1, use_symbols=1, exclude_amb=1;

            printf("Length (8-128) [16]: ");
            if (fgets(input, sizeof(input), stdin)) {
                int t = atoi(input);
                if (t >= 8 && t <= 128) length = t;
            }

            printf("Lowercase? (y/n) [y]: ");
            if (fgets(input, sizeof(input), stdin) && (input[0]=='n'||input[0]=='N')) use_lower=0;
            printf("Uppercase? (y/n) [y]: ");
            if (fgets(input, sizeof(input), stdin) && (input[0]=='n'||input[0]=='N')) use_upper=0;
            printf("Digits? (y/n) [y]: ");
            if (fgets(input, sizeof(input), stdin) && (input[0]=='n'||input[0]=='N')) use_digits=0;
            printf("Symbols? (y/n) [y]: ");
            if (fgets(input, sizeof(input), stdin) && (input[0]=='n'||input[0]=='N')) use_symbols=0;
            printf("Exclude ambiguous (0O1lI)? (y/n) [y]: ");
            if (fgets(input, sizeof(input), stdin) && (input[0]=='n'||input[0]=='N')) exclude_amb=0;

            if (generate_password(password, length, use_lower, use_upper, use_digits, use_symbols, exclude_amb) == 0) {
                printf("\nGenerated: %s\n", password);
                if (choice == 3) {
                    analyze_password(password, &analysis);
                    print_analysis(&analysis, password);
                }
            }
        }
        else if (choice == 2) {
            printf("Enter password: ");
            if (fgets(input, sizeof(input), stdin)) {
                input[strcspn(input, "\r\n")] = 0;
                analyze_password(input, &analysis);
                print_analysis(&analysis, input);
            }
        }
        else if (choice == 4) {
            printf("Text to encrypt: ");
            if (!fgets(input, sizeof(input), stdin)) continue;
            input[strcspn(input, "\r\n")] = 0;

            printf("Master passphrase: ");
            char pass[128];
            if (!fgets(pass, sizeof(pass), stdin)) continue;
            pass[strcspn(pass, "\r\n")] = 0;

            if (aes256_encrypt(input, pass, hex_buf, sizeof(hex_buf)) == 0) {
                printf("\nEncrypted (hex):\n%s\n", hex_buf);
            } else {
                printf("Encryption failed.\n");
            }
            memset(pass, 0, sizeof(pass));
        }
        else if (choice == 5) {
            printf("Enter hex (IV + ciphertext): ");
            if (!fgets(hex_buf, sizeof(hex_buf), stdin)) continue;
            hex_buf[strcspn(hex_buf, "\r\n")] = 0;

            printf("Master passphrase: ");
            char pass[128];
            if (!fgets(pass, sizeof(pass), stdin)) continue;
            pass[strcspn(pass, "\r\n")] = 0;

            if (aes256_decrypt(hex_buf, pass, decrypted, sizeof(decrypted)) == 0) {
                printf("\nDecrypted: %s\n", decrypted);
            } else {
                printf("Decryption failed (wrong key or bad data).\n");
            }
            memset(pass, 0, sizeof(pass));
            memset(decrypted, 0, sizeof(decrypted));
        }
    }

    memset(password, 0, sizeof(password));
    printf("Goodbye.\n");
    return 0;
}
