#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <jansson.h>
#include <sys/stat.h>
#include "common.h"
#include "http_client.h"

// --- Key Paths ---
#define BOB_USERNAME "bob"
#define BOB_KEYS_DIR "/app/my_keys"
#define BOB_IK_PRIV_FILE BOB_KEYS_DIR "/bob_ik.priv"
#define BOB_IK_PUB_FILE BOB_KEYS_DIR "/bob_ik.pub"
#define BOB_SPK_PRIV_FILE BOB_KEYS_DIR "/bob_spk.priv"
#define BOB_SPK_PUB_FILE BOB_KEYS_DIR "/bob_spk.pub"
#define BOB_OPK_PRIV_DIR BOB_KEYS_DIR "/opk/"
#define BOB_SK_FILE_PREFIX BOB_KEYS_DIR "/sk_with_"

#define URL_BUFFER_SIZE 256
#define SHARED_KEY_SIZE 32
#define SIGNATURE_NONCE_SIZE 64
#define KDF_INPUT_MAX_SIZE 160
#define NUM_OPKS 10 // Number of OPKs to generate

/**
 * @brief Get the path to the shared key file for a given recipient.
 * @param path_buf Buffer to store the path.
 * @param buf_len Length of the buffer.
 * @param recipient Recipient username.
 */
void get_sk_path(char *path_buf, size_t buf_len, const char *recipient) {
    snprintf(path_buf, buf_len, "%s%s.key", BOB_SK_FILE_PREFIX, recipient);
}


/**
 * @brief Get the path to the OPK private key file for a given key ID.
 * @param path_buf Buffer to store the path.
 * @param buf_len Length of the buffer.
 * @param key_id OPK key ID.
 */
void get_opk_path(char *path_buf, size_t buf_len, int key_id) {
    snprintf(path_buf, buf_len, "%s%d.priv", BOB_OPK_PRIV_DIR, key_id);
}


// --- 1. Bob Register ---
int bob_register() {
    printf("--- Bob: Registering ---\n");
    if (file_exists(BOB_IK_PRIV_FILE)) {
        int c;
        while(1){
            printf("WARNING: Keys already exist at %s.\n", BOB_KEYS_DIR);
            printf("Are you sure you want to overwrite them? (y/n): ");
            fflush(stdout); // Make sure prompt is displayed before input
            c = fgetc(stdin);
            
            // Clear the rest of the input buffer
            int extra;
            while ((extra = fgetc(stdin)) != '\n' && extra != EOF); 

            if (c == 'y' || c == 'Y') {
                printf("Proceeding with re-registration...\n\n");
                break; // Valid input, continue registration
            }
            
            if (c == 'n' || c == 'N') {
                printf("New registration aborted.\n");
                return -1;
            }
            
            // If neither, print error and loop again
            printf("Invalid input. Please enter 'y' or 'n'.\n\n");
        }
    }

    mkdir(BOB_KEYS_DIR, 0700);
    mkdir(BOB_OPK_PRIV_DIR, 0700);

    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char signature[crypto_sign_ed25519_BYTES];
    
    char *ik_pub_b64 = NULL;
    char *spk_pub_b64 = NULL;
    char *sig_b64 = NULL;
    json_t *ik_data = NULL;
    json_t *bundle_data = NULL;
    json_t *opks_json_list = NULL;
    ResponseInfo resp = {0};
    int ret = -1;

    // --- 1a. Generate Identity Key (IK) ---
    randombytes_buf(ik_priv, sizeof(ik_priv));
    priv_to_curve25519_pub(ik_pub, ik_priv);
    if (write_file(BOB_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        write_file(BOB_IK_PUB_FILE, ik_pub, sizeof(ik_pub)) != 0) {
        fprintf(stderr, "Failed to write Bob's IK.\n");
        goto cleanup;
    }
    
    // --- 1b. Register IK with Server ---
    ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    if (!ik_pub_b64) goto cleanup;
    ik_data = json_pack("{s:s, s:s}", "username", BOB_USERNAME, "ik_b64", ik_pub_b64);
    
    if (http_post_json(SERVER_URL "/register_ik", ik_data, &resp) != 0 || (resp.http_code != 201)) {
        fprintf(stderr, "Failed to register IK with server. Code: %ld\n", resp.http_code);
        fprintf(stderr, "Server response: %s\n", resp.body);
        goto cleanup;
    }
    printf("Bob registered IK successfully.\n");
    cleanup_response(&resp);

    // --- 2. Generate Signed Prekey (SPK) ---
    randombytes_buf(spk_priv, sizeof(spk_priv));
    priv_to_curve25519_pub(spk_pub, spk_priv);

    // --- 3. Sign SPK with IK's private key ---
    uint8_t sign_nonce[SIGNATURE_NONCE_SIZE];
    randombytes_buf(sign_nonce, SIGNATURE_NONCE_SIZE);
    unsigned char bob_private_signing_key[crypto_scalarmult_curve25519_BYTES];
    priv_force_sign(bob_private_signing_key, ik_priv, 0);
    ed25519_priv_sign(signature, bob_private_signing_key, spk_pub, crypto_scalarmult_curve25519_BYTES, sign_nonce);
    printf("SPK signed with IK successfully.\n");

    // --- 4. Save local SPK ---
    if (write_file(BOB_SPK_PRIV_FILE, spk_priv, sizeof(spk_priv)) != 0 ||
        write_file(BOB_SPK_PUB_FILE, spk_pub, sizeof(spk_pub)) != 0) {
        fprintf(stderr, "Failed to write Bob's SPK.\n"); goto cleanup;
    }

    // --- 5. Generate One-Time Prekeys (OPKs) ---
    printf("Generating %d One-Time Prekeys...\n", NUM_OPKS);
    opks_json_list = json_array();
    for (int i = 0; i < NUM_OPKS; i++) {
        unsigned char opk_priv[crypto_scalarmult_curve25519_BYTES];
        unsigned char opk_pub[crypto_scalarmult_curve25519_BYTES];
        
        randombytes_buf(opk_priv, sizeof(opk_priv));
        priv_to_curve25519_pub(opk_pub, opk_priv);
        
        // Save private key locally
        char opk_priv_path[128];
        get_opk_path(opk_priv_path, sizeof(opk_priv_path), i);
        if (write_file(opk_priv_path, opk_priv, sizeof(opk_priv)) != 0) {
            fprintf(stderr, "Failed to write OPK %d\n", i);
            goto cleanup;
        }
        
        // Add public key to JSON list for upload
        char *opk_pub_b64 = b64_encode(opk_pub, sizeof(opk_pub));
        json_t *opk_json = json_pack("{s:i, s:s}", "id", i, "key", opk_pub_b64);
        json_array_append_new(opks_json_list, opk_json);
        free(opk_pub_b64);
        
        sodium_memzero(opk_priv, sizeof(opk_priv));
    }
    printf("Generated and saved %d OPKs.\n", NUM_OPKS);

    // --- 6. Create Bundle JSON to upload ---
    spk_pub_b64 = b64_encode(spk_pub, sizeof(spk_pub));
    sig_b64 = b64_encode(signature, sizeof(signature));
    if (!spk_pub_b64 || !sig_b64) goto cleanup;

    bundle_data = json_pack("{s:s, s:s, s:s, s:o}",
                             "username", BOB_USERNAME,
                             "spk_b64", spk_pub_b64,
                             "spk_sig_b64", sig_b64,
                             "opks_b64", opks_json_list);
    
    // --- 7. Upload Bundle to server ---
    if (http_post_json(SERVER_URL "/register_bundle", bundle_data, &resp) != 0 || resp.http_code != 201) {
        fprintf(stderr, "Failed to register bundle with server. Code: %ld\n", resp.http_code);
        fprintf(stderr, "Server response: %s\n", resp.body);
        goto cleanup;
    }

    printf("Bob's bundle registered successfully.\n");
    ret = 0;

cleanup:
    sodium_memzero(ik_priv, sizeof(ik_priv));
    sodium_memzero(spk_priv, sizeof(spk_priv));
    sodium_memzero(bob_private_signing_key, sizeof(bob_private_signing_key));
    
    free(ik_pub_b64);
    free(spk_pub_b64);
    free(sig_b64);
    if (ik_data) json_decref(ik_data);
    if (bundle_data) json_decref(bundle_data);
    cleanup_response(&resp);
    return ret;
}

// --- 2. Bob Read Initial X3DH Message ---
int bob_read_initial_message() {
    printf("--- Bob: Checking for initial message ---\n");
    
    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char spk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char opk_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char alice_ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char alice_ek_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char ad[crypto_scalarmult_curve25519_BYTES * 2];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char sk[SHARED_KEY_SIZE];
    memset(sk, 0, sizeof(sk));
    
    // Max size is F(32) + DH1(32) + DH2(32) + DH3(32) + DH4(32) = 160
    unsigned char kdf_input[KDF_INPUT_MAX_SIZE];
    size_t kdf_input_len = 0;

    json_t *msg = NULL;
    ResponseInfo resp = {0};
    unsigned char *ciphertext = NULL;
    unsigned char *decrypted_msg = NULL;
    int ret = -1;
    int has_opk = 0;
    int opk_id = -1;

    // 1. Fetch message from server
    char url_buf[URL_BUFFER_SIZE];
    snprintf(url_buf, URL_BUFFER_SIZE, SERVER_URL "/get_initial_message/%s", BOB_USERNAME);

    if (http_get(url_buf, &resp) != 0) {
        fprintf(stderr, "Failed to connect to server.\n");
        goto cleanup;
    }
    
    if (resp.http_code == 404) {
        printf("No new initial messages for Bob.\n");
        ret = 0;
        goto cleanup;
    }
    
    if (resp.http_code != 200) {
        fprintf(stderr, "Failed to get message for Bob. Code: %ld\n", resp.http_code);
        fprintf(stderr, "Server response: %s\n", resp.body);
        goto cleanup;
    }
    printf("Received initial message from server.\n");

    // 2. Parse the message
    json_error_t error;
    msg = json_loads(resp.body, 0, &error);
    if (!msg) {
        fprintf(stderr, "Failed to parse message JSON: %s\n", error.text);
        goto cleanup;
    }

    const char *from_user = NULL;
    const char *ik_b64 = NULL;
    const char *ek_b64 = NULL;
    const char *ciphertext_b64 = NULL;
    const char *ad_b64 = NULL;
    const char *nonce_b64 = NULL;
    
    json_unpack_ex(msg, &error, 0, "{s:s, s:s, s:s, s:i, s:s, s:s, s:s}",
                   "from_user", &from_user,
                   "ik_b64", &ik_b64,
                   "ek_b64", &ek_b64,
                   "opk_id", &opk_id,
                   "ciphertext_b64", &ciphertext_b64,
                   "ad_b64", &ad_b64,
                   "nonce_b64", &nonce_b64);
    
    if (!from_user || !ik_b64 || !ek_b64 || !ciphertext_b64 || !ad_b64 || !nonce_b64) {
        fprintf(stderr, "Failed to unpack message JSON: %s\n", error.text);
        goto cleanup;
    }
    printf("Processing initial message from: %s\n", from_user);

    // 3. Load Bob's private keys
    if (read_file(BOB_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        read_file(BOB_SPK_PRIV_FILE, spk_priv, sizeof(spk_priv)) != 0) {
        fprintf(stderr, "Failed to read Bob's local keys. Have you registered?\n");
        goto cleanup;
    }
    
    has_opk = (opk_id != -1);
    if (has_opk) {
        char opk_priv_path[128];
        get_opk_path(opk_priv_path, sizeof(opk_priv_path), opk_id);
        if (read_file(opk_priv_path, opk_priv, sizeof(opk_priv)) != 0) {
            fprintf(stderr, "Failed to read OPK %d private key!\n", opk_id);
            goto cleanup;
        }
        printf("Loaded OPK %d private key.\n", opk_id);
    }

    // 4. Decode Alice's public keys, AD, and nonce
    if (b64_decode(ik_b64, alice_ik_pub, sizeof(alice_ik_pub)) != sizeof(alice_ik_pub) ||
        b64_decode(ek_b64, alice_ek_pub, sizeof(alice_ek_pub)) != sizeof(alice_ek_pub) ||
        b64_decode(ad_b64, ad, sizeof(ad)) != sizeof(ad) ||
        b64_decode(nonce_b64, nonce, sizeof(nonce)) != sizeof(nonce)) {
    
        fprintf(stderr, "Failed to decode base64 keys/AD/nonce from message.\n");
        goto cleanup;
    }

    // 5. Perform DH calculations
    unsigned char dh1[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh2[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh3[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh4[crypto_scalarmult_curve25519_BYTES];

    if (x25519(dh1, spk_priv, alice_ik_pub) != 0 ||
        x25519(dh2, ik_priv, alice_ek_pub) != 0 ||
        x25519(dh3, spk_priv, alice_ek_pub) != 0) {
        fprintf(stderr, "DH calculation failed.\n");
        goto cleanup;
    }
    
    if (has_opk) {
        if (x25519(dh4, opk_priv, alice_ek_pub) != 0) {
            fprintf(stderr, "DH4 calculation failed.\n");
            goto cleanup;
        }
    }

    // 6. Concatenate DH outputs (must be same order as Alice)
    unsigned char f_padding[32];
    memset(f_padding, 0xFF, sizeof(f_padding));

    kdf_input_len = 32 + 32 + 32 + 32; // F + DH1 + DH2 + DH3

    memcpy(kdf_input, f_padding, 32);
    memcpy(kdf_input + 32, dh1, 32);
    memcpy(kdf_input + 64, dh2, 32);
    memcpy(kdf_input + 96, dh3, 32);
    if (has_opk) {
        memcpy(kdf_input + 128, dh4, 32);
        kdf_input_len += 32;
    }

    // 7. Derive Shared Key (SK)
    if (hkdf(sk, sizeof(sk), kdf_input, kdf_input_len, X3DH_INFO_STRING) != 0) {
        fprintf(stderr, "KDF failed.\n");
        goto cleanup;
    }

    printf("Shared Key (SK) computed successfully (Bob).\n");
    //print_hex("SK_Bob", sk, sizeof(sk));

    // Save SK to file
    char sk_path[256];
    get_sk_path(sk_path, sizeof(sk_path), from_user);
    if (write_file(sk_path, sk, sizeof(sk)) != 0) {
        fprintf(stderr, "CRITICAL: Failed to save shared key to %s!\n", sk_path);
        goto cleanup;
    }
    printf("Shared key saved to %s\n", sk_path);

    // 8. Decrypt message
    size_t ciphertext_len = 0;
    ciphertext = b64_decode_ex(ciphertext_b64, 0, &ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Failed to decode ciphertext.\n");
        goto cleanup;
    }

    unsigned long long decrypted_len;
    decrypted_msg = malloc(ciphertext_len); // Decrypted len <= Ciphertext len
    if (!decrypted_msg) {
        fprintf(stderr, "Failed to malloc for decrypted message.\n");
        goto cleanup;
    }
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len,
            NULL, // nsec (not used)
            ciphertext, ciphertext_len,
            ad, sizeof(ad), // Associated Data
            nonce, sk) != 0) {
        fprintf(stderr, "!!! DECRYPTION FAILED! Invalid key or tampered message. !!!\n");
        goto cleanup;
    }
    
    decrypted_msg[decrypted_len] = '\0';
    printf("--- Initial Message Received ---\n");
    printf("[%s]: %s\n", from_user, (char *)decrypted_msg);
    printf("--------------------------------\n");
    ret = 0;

cleanup:
    sodium_memzero(ik_priv, sizeof(ik_priv));
    sodium_memzero(spk_priv, sizeof(spk_priv));
    sodium_memzero(opk_priv, sizeof(opk_priv));
    sodium_memzero(kdf_input, sizeof(kdf_input));
    sodium_memzero(sk, sizeof(sk));
    
    if (msg) json_decref(msg);
    cleanup_response(&resp);
    free(ciphertext);
    free(decrypted_msg);
    
    // Delete the OPK private key
    if (has_opk) {
        char opk_priv_path[128];
        get_opk_path(opk_priv_path, sizeof(opk_priv_path), opk_id);
        if (remove(opk_priv_path) == 0) {
             printf("Used OPK %d private key deleted.\n", opk_id);
        } else {
             perror("Warning: Failed to delete OPK private key");
        }
    }
    return ret;
}

// --- 3. Bob Send Chat Message (Post-X3DH) ---
int bob_send_chat_message(const char *recipient) {
    // 1. Load the shared key
    unsigned char sk[SHARED_KEY_SIZE];
    char sk_path[256];
    get_sk_path(sk_path, sizeof(sk_path), recipient);

    if (read_file(sk_path, sk, sizeof(sk)) != 0) {
        fprintf(stderr, "No shared key found for %s. Run 'read_init' to get initial message first.\n", recipient);
        return -1;
    }
    
    // 2. Get message from stdin
    char *message_text = read_message_from_stdin();
    if (!message_text || strlen(message_text) == 0) {
        fprintf(stderr, "No message entered. Aborting.\n");
        free(message_text);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }
    
    // 3. Encrypt message
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce)); // Fresh nonce

    unsigned long long ciphertext_len = strlen(message_text) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Failed to malloc for ciphertext\n");
        free(message_text);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }

    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
        (const unsigned char *)message_text, strlen(message_text),
        NULL, 0, // No Associated Data
        NULL, nonce, sk);
    
    free(message_text);
    
    // 4. Encode for JSON
    char *ciphertext_b64 = b64_encode(ciphertext, ciphertext_len);
    char *nonce_b64 = b64_encode(nonce, sizeof(nonce));
    free(ciphertext);
    
    if (!ciphertext_b64 || !nonce_b64) {
        fprintf(stderr, "Failed to b64-encode chat message.\n");
        free(ciphertext_b64);
        free(nonce_b64);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }
    
    // 5. Pack JSON and send
    json_t *msg_data = json_pack("{s:s, s:s, s:s, s:s}",
                                 "from", BOB_USERNAME,
                                 "to", recipient,
                                 "ciphertext_b64", ciphertext_b64,
                                 "nonce_b64", nonce_b64);
    ResponseInfo resp = {0};
    if (http_post_json(SERVER_URL "/send_chat_message", msg_data, &resp) != 0 || resp.http_code != 201) {
        fprintf(stderr, "Failed to send chat message to server. Code: %ld\n", resp.http_code);
        fprintf(stderr, "Server response: %s\n", resp.body);
    } else {
        printf("Message sent.\n");
    }
    
    // 6. Cleanup
    free(ciphertext_b64);
    free(nonce_b64);
    json_decref(msg_data);
    cleanup_response(&resp);
    sodium_memzero(sk, sizeof(sk));
    return 0;
}

// --- 4. Bob Read Chat Messages (Post-X3DH) ---
int bob_read_chat_messages(const char *sender) {
    // 1. Load the shared key
    unsigned char sk[SHARED_KEY_SIZE];
    char sk_path[256];
    get_sk_path(sk_path, sizeof(sk_path), sender);

    if (read_file(sk_path, sk, sizeof(sk)) != 0) {
        fprintf(stderr, "No shared key found for %s. Cannot decrypt messages.\n", sender);
        return -1;
    }
    
    // 2. Fetch messages from server
    char url_buf[URL_BUFFER_SIZE];
    snprintf(url_buf, URL_BUFFER_SIZE, SERVER_URL "/get_chat_messages/%s/from/%s", BOB_USERNAME, sender);
    ResponseInfo resp = {0};
    if (http_get(url_buf, &resp) != 0 || resp.http_code != 200) {
        fprintf(stderr, "Failed to get chat messages. Code: %ld\n", resp.http_code);
        fprintf(stderr, "Server response: %s\n", resp.body);
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    // 3. Parse the message list (JSON array)
    json_error_t error;
    json_t *msg_list = json_loads(resp.body, 0, &error);
    
    if (!msg_list) {
        fprintf(stderr, "Failed to parse message list JSON: %s\n", error.text);
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    if (!json_is_array(msg_list)) {
        fprintf(stderr, "Server response is not a JSON array.\n");
        json_decref(msg_list);
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return -1;
    }
    
    size_t count = json_array_size(msg_list);
    if (count == 0) {
        printf("No new messages from %s.\n", sender);
        json_decref(msg_list);
        sodium_memzero(sk, sizeof(sk));
        cleanup_response(&resp);
        return 0;
    }
    
    printf("--- Received %zu new message(s) from %s ---\n", count, sender);
    
    // 4. Iterate, decode, and decrypt
    for (size_t i = 0; i < count; i++) {
        json_t *msg = json_array_get(msg_list, i);
        const char *ciphertext_b64 = NULL;
        const char *nonce_b64 = NULL;
        
        json_unpack_ex(msg, &error, 0, "{s:s, s:s}",
                       "ciphertext_b64", &ciphertext_b64,
                       "nonce_b64", &nonce_b64);
        
        if (!ciphertext_b64 || !nonce_b64) {
            fprintf(stderr, "Failed to unpack message %zu.\n", i);
            continue;
        }
        
        // Decode
        size_t ciphertext_len = 0;
        unsigned char *ciphertext = b64_decode_ex(ciphertext_b64, 0, &ciphertext_len);
        
        unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        if (b64_decode(nonce_b64, nonce, sizeof(nonce)) != sizeof(nonce)) {
            fprintf(stderr, "Failed to decode nonce for message %zu.\n", i);
            free(ciphertext);
            continue;
        }
        
        if (!ciphertext) {
            fprintf(stderr, "Failed to decode ciphertext for message %zu.\n", i);
            continue;
        }
        
        // Decrypt
        unsigned long long decrypted_len;
        unsigned char *decrypted_msg = malloc(ciphertext_len);
        if (!decrypted_msg) {
             fprintf(stderr, "Failed to malloc for decrypted message %zu.\n", i);
             free(ciphertext);
             continue;
        }
        
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted_msg, &decrypted_len,
                NULL, // nsec (not used)
                ciphertext, ciphertext_len,
                NULL, 0, // No Associated Data
                nonce, sk) != 0) {
            fprintf(stderr, "[Message %zu: DECRYPTION FAILED!]\n", i);
        } else {
            decrypted_msg[decrypted_len] = '\0';
            printf("[%s]: %s\n", sender, (char *)decrypted_msg);
        }
        
        free(ciphertext);
        free(decrypted_msg);
    }
    
    printf("------------------------------------------\n");
    json_decref(msg_list);
    sodium_memzero(sk, sizeof(sk));
    cleanup_response(&resp);
    return 0;
}


// --- Main Function ---
int main(int argc, char *argv[]) {
    if (sodium_init() == -1) {
        printf("Failed to initialize libsodium!\n");
        return 1;
    }
    if (xeddsa_init() < 0) {
        fprintf(stderr, "Failed to initialize libxeddsa!\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args]\n", argv[0]);
        fprintf(stderr, "Commands:\n");
        fprintf(stderr, "  register (Run every time you want to register new keys)\n");
        fprintf(stderr, "  read_init (Run once to start chat)\n");
        fprintf(stderr, "  send <recipient>\n");
        fprintf(stderr, "  read <sender>\n");
        return 1;
    }

    int ret = 0;
    const char *command = argv[1];

    if (strcmp(command, "register") == 0) {
        if (argc != 2) {
             fprintf(stderr, "Usage: %s register\n", argv[0]); return 1;
        }
        ret = bob_register();
        
    } else if (strcmp(command, "read_init") == 0) {
        if (argc != 2) {
            fprintf(stderr, "Usage: %s read_init\n", argv[0]); return 1;
        }
        ret = bob_read_initial_message();
        
    } else if (strcmp(command, "send") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s send <recipient_username>\n", argv[0]); return 1;
        }
        ret = bob_send_chat_message(argv[2]);
        
    } else if (strcmp(command, "read") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s read <sender_username>\n", argv[0]); return 1;
        }
        ret = bob_read_chat_messages(argv[2]);
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        ret = 1;
    }

    return ret;
}