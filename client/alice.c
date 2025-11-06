#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <jansson.h>
#include <sys/stat.h>
#include "common.h"
#include "http_client.h"

// --- Key Paths ---
#define ALICE_USERNAME "alice"
#define ALICE_KEYS_DIR "/app/my_keys"
#define ALICE_IK_PRIV_FILE ALICE_KEYS_DIR "/alice_ik.priv"
#define ALICE_IK_PUB_FILE ALICE_KEYS_DIR "/alice_ik.pub"
#define ALICE_SK_FILE_PREFIX ALICE_KEYS_DIR "/sk_with_"

#define URL_BUFFER_SIZE 256
#define SHARED_KEY_SIZE 32
#define KDF_INPUT_MAX_SIZE 160

/**
 * @brief Get the path to the shared key file for a given recipient.
 * @param path_buf Buffer to store the path.
 * @param buf_len Length of the buffer.
 * @param recipient Recipient username.
 */
void get_sk_path(char *path_buf, size_t buf_len, const char *recipient) {
    snprintf(path_buf, buf_len, "%s%s.key", ALICE_SK_FILE_PREFIX, recipient);
}


// --- 1. Alice Register ---
int alice_register() {
    printf("--- Alice: Registering ---\n");
    if (file_exists(ALICE_IK_PRIV_FILE)) {
        int c, extra;
        while(1){
            printf("WARNING: Keys already exist at %s.\n", ALICE_KEYS_DIR);
            printf("Are you sure you want to overwrite them? (y/n): ");
            fflush(stdout); // Make sure prompt is displayed before input
            c = fgetc(stdin);
            
            // Clear the rest of the input buffer
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

    mkdir(ALICE_KEYS_DIR, 0700);

    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
    char *ik_pub_b64 = NULL;
    json_t *upload_data = NULL;
    ResponseInfo resp = {0};
    int ret = -1;

    // 1. Generate Identity Key (IK)
    randombytes_buf(ik_priv, sizeof(ik_priv));
    priv_to_curve25519_pub(ik_pub, ik_priv);

    // 2. Save keys locally
    if (write_file(ALICE_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        write_file(ALICE_IK_PUB_FILE, ik_pub, sizeof(ik_pub)) != 0) {
        fprintf(stderr, "Failed to write Alice's local keys.\n");
        goto cleanup;
    }

    // 3. Create JSON to upload
    ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    if (!ik_pub_b64) goto cleanup;
    upload_data = json_pack("{s:s, s:s}",
                            "username", ALICE_USERNAME,
                            "ik_b64", ik_pub_b64);
    
    // 4. "Upload" to server
    if (http_post_json(SERVER_URL "/register_ik", upload_data, &resp) != 0 || (resp.http_code != 201)) {
        fprintf(stderr, "Failed to register IK with server. Code: %ld\n", resp.http_code);
        fprintf(stderr, "Server response: %s\n", resp.body);
        goto cleanup;
    }

    printf("Alice registered IK successfully.\n");
    ret = 0;

cleanup:
    sodium_memzero(ik_priv, sizeof(ik_priv));
    free(ik_pub_b64);
    if (upload_data) json_decref(upload_data);
    cleanup_response(&resp);
    return ret;
}

// --- 2. Alice Send Initial X3DH Message ---
int alice_send_initial_message(const char *recipient) {
    printf("--- Alice: Initializing session with %s ---\n", recipient);

    unsigned char ik_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char ek_priv[crypto_scalarmult_curve25519_BYTES];
    unsigned char ek_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_ik_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_spk_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char bob_opk_pub[crypto_scalarmult_curve25519_BYTES];
    unsigned char signature[crypto_sign_ed25519_BYTES];
    
    // Max size is F(32) + DH1(32) + DH2(32) + DH3(32) + DH4(32) = 160
    unsigned char kdf_input[KDF_INPUT_MAX_SIZE];
    size_t kdf_input_len = 0;
    
    char *ad_b64 = NULL;
    char *ik_pub_b64 = NULL;
    char *ek_pub_b64 = NULL;
    char *ciphertext_b64 = NULL;
    char *nonce_b64 = NULL;
    char *message_text = NULL;
    unsigned char *ciphertext = NULL;

    json_t *bundle = NULL;
    json_t *msg_data = NULL;
    
    ResponseInfo get_resp = {0};
    ResponseInfo post_resp = {0};
    int ret = -1;
    int opk_id = -1;
    int has_opk = 0;

    // 1. Load Alice's identity keys
    if (read_file(ALICE_IK_PRIV_FILE, ik_priv, sizeof(ik_priv)) != 0 ||
        read_file(ALICE_IK_PUB_FILE, ik_pub, sizeof(ik_pub)) != 0) {
        fprintf(stderr, "Failed to read Alice's local keys. Have you registered?\n");
        goto cleanup;
    }

    // 2. Generate Ephemeral Key (EK)
    randombytes_buf(ek_priv, sizeof(ek_priv));
    priv_to_curve25519_pub(ek_pub, ek_priv);

    // 3. Fetch recipient's bundle from server
    const char *bob_ik_b64 = NULL;
    const char *bob_spk_b64 = NULL;
    const char *bob_sig_b64 = NULL;
    const char *bob_opk_b64 = NULL;
    char url_buf[URL_BUFFER_SIZE];
    snprintf(url_buf, sizeof(url_buf), SERVER_URL "/get_bundle/%s", recipient);
    printf("Fetching key bundle for %s...\n", recipient);

    if (http_get(url_buf, &get_resp) != 0 || get_resp.http_code != 200) {
        fprintf(stderr, "Failed to get bundle for %s. Code: %ld\n", recipient, get_resp.http_code);
        fprintf(stderr, "Server response: %s\n", get_resp.body);
        goto cleanup;
    }
    printf("Key bundle fetched.\n");

    // 4. Parse the bundle
    json_error_t error;
    bundle = json_loads(get_resp.body, 0, &error);
    
    if (!bundle) {
        fprintf(stderr, "Failed to parse server bundle JSON: %s\n", error.text);
        goto cleanup;
    }
    
    json_unpack_ex(bundle, &error, 0, "{s:s, s:s, s:s, s?:s, s?:i}",
                   "ik_b64", &bob_ik_b64,
                   "spk_b64", &bob_spk_b64,
                   "spk_sig_b64", &bob_sig_b64,
                   "opk_b64", &bob_opk_b64,
                   "opk_id", &opk_id);
    
    if (!bob_ik_b64 || !bob_spk_b64 || !bob_sig_b64) {
        fprintf(stderr, "Failed to unpack bundle JSON: %s\n", error.text);
        goto cleanup;
    }
    
    has_opk = (opk_id != -1 && bob_opk_b64 != NULL);
    
    // Decode all the keys
    if (b64_decode(bob_ik_b64, bob_ik_pub, sizeof(bob_ik_pub)) != sizeof(bob_ik_pub) ||
        b64_decode(bob_spk_b64, bob_spk_pub, sizeof(bob_spk_pub)) != sizeof(bob_spk_pub) ||
        b64_decode(bob_sig_b64, signature, sizeof(signature)) != sizeof(signature)) {
        fprintf(stderr, "Failed to decode base64 keys from bundle.\n");
        goto cleanup;
    }
    
    if (has_opk) {
        if (b64_decode(bob_opk_b64, bob_opk_pub, sizeof(bob_opk_pub)) != sizeof(bob_opk_pub)) {
            fprintf(stderr, "Failed to decode OPK from bundle.\n");
            goto cleanup;
        }
    }

    // 5. Verify SPK signature
    unsigned char ed_bob_ik_pub[crypto_sign_ed25519_PUBLICKEYBYTES];
    curve25519_pub_to_ed25519_pub(ed_bob_ik_pub, bob_ik_pub, 0);

    if (ed25519_verify(signature, ed_bob_ik_pub, bob_spk_pub, sizeof(bob_spk_pub)) != 0) {
        fprintf(stderr, "Invalid SPK signature! Aborting.\n");
        goto cleanup;
    }
    printf("SPK signature verified successfully.\n");
    if (has_opk) {
        printf("Using One-Time Prekey (OPK) id: %d\n", opk_id);
    } else {
        printf("No OPK available. Proceeding without one.\n");
    }

    // 6. Perform DH calculations
    unsigned char dh1[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh2[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh3[crypto_scalarmult_curve25519_BYTES];
    unsigned char dh4[crypto_scalarmult_curve25519_BYTES];

    if (x25519(dh1, ik_priv, bob_spk_pub) != 0 ||
        x25519(dh2, ek_priv, bob_ik_pub) != 0 ||
        x25519(dh3, ek_priv, bob_spk_pub) != 0) {
        fprintf(stderr, "DH calculation failed.\n");
        goto cleanup;
    }
    
    if (has_opk) {
        if (x25519(dh4, ek_priv, bob_opk_pub) != 0) {
            fprintf(stderr, "DH4 calculation failed.\n");
            goto cleanup;
        }
    }

    // 7. Concatenate DH outputs
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

    // 8. Derive Shared Key (SK)
    unsigned char sk[SHARED_KEY_SIZE];
    if (hkdf(sk, sizeof(sk), kdf_input, kdf_input_len, X3DH_INFO_STRING) != 0) {
        fprintf(stderr, "KDF failed.\n");
        goto cleanup;
    }

    printf("Shared Key (SK) computed successfully (Alice).\n");
    //print_hex("SK_Alice", sk, sizeof(sk));

    // Save SK to file ---
    char sk_path[256];
    get_sk_path(sk_path, sizeof(sk_path), recipient);
    if (write_file(sk_path, sk, sizeof(sk)) != 0) {
        fprintf(stderr, "Failed to save shared key to %s!\n", sk_path);
        goto cleanup;
    }
    printf("Shared key saved to %s\n", sk_path);

    // 9. Calculate Associated Data (AD)
    unsigned char ad[crypto_scalarmult_curve25519_BYTES * 2];
    memcpy(ad, ik_pub, sizeof(ik_pub));
    memcpy(ad + sizeof(ik_pub), bob_ik_pub, sizeof(bob_ik_pub));
    ad_b64 = b64_encode(ad, sizeof(ad));

    // 10. Get message, encrypt, and package
    message_text = read_message_from_stdin();
    if (!message_text || strlen(message_text) == 0) {
        fprintf(stderr, "No message entered. Aborting.\n");
        goto cleanup;
    }
    
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    unsigned long long ciphertext_len = strlen(message_text) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
    ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Failed to malloc for ciphertext\n");
        goto cleanup;
    }

    crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len,
        (const unsigned char *)message_text, strlen(message_text),
        ad, sizeof(ad), // Associated Data
        NULL, nonce, sk);
    
    // 11. B64-encode everything for JSON
    ik_pub_b64 = b64_encode(ik_pub, sizeof(ik_pub));
    ek_pub_b64 = b64_encode(ek_pub, sizeof(ek_pub));
    ciphertext_b64 = b64_encode(ciphertext, ciphertext_len);
    nonce_b64 = b64_encode(nonce, sizeof(nonce));

    if (!ik_pub_b64 || !ek_pub_b64 || !ciphertext_b64 || !ad_b64 || !nonce_b64) {
        fprintf(stderr, "Failed to b64-encode keys/ciphertext for JSON\n");
        goto cleanup;
    }

    // 12. Send initial message to Bob
    msg_data = json_pack("{s:s, s:s, s:s, s:s, s:i, s:s, s:s, s:s}",
                         "from", ALICE_USERNAME,
                         "to", recipient,
                         "ik_b64", ik_pub_b64,
                         "ek_b64", ek_pub_b64,
                         "opk_id", opk_id,
                         "ciphertext_b64", ciphertext_b64,
                         "ad_b64", ad_b64,
                         "nonce_b64", nonce_b64);

    if (http_post_json(SERVER_URL "/send_initial_message", msg_data, &post_resp) != 0 || post_resp.http_code != 201) {
        fprintf(stderr, "Failed to send initial message to server. Code: %ld\n", post_resp.http_code);
        fprintf(stderr, "Server response: %s\n", post_resp.body);
        goto cleanup;
    }

    printf("Initial message sent to server for %s.\n", recipient);
    ret = 0;

cleanup:
    sodium_memzero(ek_priv, sizeof(ek_priv));
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    sodium_memzero(dh4, sizeof(dh4));
    sodium_memzero(kdf_input, sizeof(kdf_input));
    sodium_memzero(sk, sizeof(sk));

    free(ad_b64);
    free(ik_pub_b64);
    free(ek_pub_b64);
    free(ciphertext_b64);
    free(nonce_b64);
    free(message_text);
    free(ciphertext);
    if (bundle) json_decref(bundle);
    if (msg_data) json_decref(msg_data);
    
    cleanup_response(&get_resp);
    cleanup_response(&post_resp);

    return ret;
}

// --- 3. Alice Send Chat Message (Post-X3DH) ---
int alice_send_chat_message(const char *recipient) {
    // 1. Load the shared key
    unsigned char sk[SHARED_KEY_SIZE];
    char sk_path[256];
    get_sk_path(sk_path, sizeof(sk_path), recipient);

    if (read_file(sk_path, sk, sizeof(sk)) != 0) {
        fprintf(stderr, "No shared key found for %s. Run 'init_message %s' first.\n", recipient, recipient);
        return -1;
    }
    
    // 2. Get message from stdin
    char *message_text = read_message_from_stdin();
    if (!message_text || strlen(message_text) == 0) {
        fprintf(stderr, "No message entered...\n");
        free(message_text);
        sodium_memzero(sk, sizeof(sk));
        return -1;
    }
    
    // 3. Encrypt message
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

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
                                 "from", ALICE_USERNAME,
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

// --- 4. Alice Read Chat Messages (Post-X3DH) ---
int alice_read_chat_messages(const char *sender) {
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
    snprintf(url_buf, URL_BUFFER_SIZE, SERVER_URL "/get_chat_messages/%s/from/%s", ALICE_USERNAME, sender);
    
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
        fprintf(stderr, "Failed to initialize libxeddsa!\n");
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
        fprintf(stderr, "  init_message <user>  (Run once to start chat)\n");
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
        ret = alice_register();
        
    } else if (strcmp(command, "init_message") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s init_message <recipient_username>\n", argv[0]); return 1;
        }
        ret = alice_send_initial_message(argv[2]);
        
    } else if (strcmp(command, "send") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s send <recipient_username>\n", argv[0]); return 1;
        }
        ret = alice_send_chat_message(argv[2]);
        
    } else if (strcmp(command, "read") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s read <sender_username>\n", argv[0]); return 1;
        }
        ret = alice_read_chat_messages(argv[2]);
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        ret = 1;
    }

    return ret;
}