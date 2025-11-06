#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include "http_client.h"

/**
 * @brief Callback for writing received data into a ResponseInfo struct.
 * @param contents Pointer to the received data.
 * @param size Size of each data element.
 * @param nmemb Number of data elements.
 * @param userp Pointer to the ResponseInfo struct.
 * @return Number of bytes actually taken care of.
 */
static size_t http_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    ResponseInfo *mem = (ResponseInfo *)userp;

    char *ptr = realloc(mem->body, mem->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->body = ptr;
    memcpy(&(mem->body[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->body[mem->size] = 0;

    return realsize;
}


/**
 * @brief Initialize a ResponseInfo struct.
 * @param resp Pointer to the ResponseInfo struct to initialize.
 */
static void init_response(ResponseInfo *resp) {
    resp->size = 0;
    resp->body = malloc(1); // Start with 1 byte
    if (resp->body) {
        resp->body[0] = '\0';
    }
    resp->http_code = 0;
}


/**
 * @brief Initialize a CURL handle with common options.
 * @param url The URL to set for the CURL handle.
 * @param resp_info Pointer to the ResponseInfo struct for writing data.
 * @return Initialized CURL handle or NULL on failure.
 */
static CURL* init_curl(const char *url, ResponseInfo *resp_info) {
    CURL *curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, http_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)resp_info);
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L); // Set a reasonable timeout
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects
    }
    return curl;
}


/**
 * @brief Free the memory allocated for the response body.
 * @param resp Pointer to the ResponseInfo struct.
 */
void cleanup_response(ResponseInfo *resp) {
    if (resp->body) {
        free(resp->body);
        resp->body = NULL;
    }
    resp->size = 0;
}


/**
 * @brief Perform an HTTP GET request.
 * @param url The full URL to get.
 * @param resp_info Pointer to an http_response struct to store results (like HTTP code).
 * @return Returns 0 on success, -1 on failure
 */
int http_get(const char *url, ResponseInfo *resp_info) {
    CURL *curl;
    CURLcode res;

    init_response(resp_info);

    curl = init_curl(url, resp_info);
    if (!curl) {
        fprintf(stderr, "init()_curl failed\n");
        return -1;
    }

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }

    // Get the HTTP response code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_info->http_code);
    curl_easy_cleanup(curl);
    return 0;
}


/**
 * @brief Perform an HTTP POST request with a JSON payload.
 * @param url The full URL to post to.
 * @param payload The json_t object to send as the body.
 * @param info Pointer to an http_response struct to store results (like HTTP code).
 * @return Returns 0 on success, -1 on failure
 */
int http_post_json(const char *url, json_t *payload, ResponseInfo *resp_info) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    char *payload_str = NULL;

    init_response(resp_info);

    curl = init_curl(url, resp_info);
    if (!curl) {
        fprintf(stderr, "init_curl() failed\n");
        return -1;
    }

    // Prepare JSON payload
    payload_str = json_dumps(payload, JSON_COMPACT);
    if (!payload_str) {
        fprintf(stderr, "json_dumps failed\n");
        curl_easy_cleanup(curl);
        return -1;
    }

    // Set headers
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_str);

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    // Get the HTTP response code
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_info->http_code);

    // Clean up
    curl_slist_free_all(headers);
    free(payload_str);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}