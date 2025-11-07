/**
 * Comprehensive unit tests for cwebsocket.
 * Tests all core functionality to achieve 100% coverage.
 */
#define UNIT_TESTING
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "cwebsocket/common.h"
#include "cwebsocket/client.h"
#include "cwebsocket/client_internal.h"

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        printf("Running test: %s... ", #name); \
        fflush(stdout); \
    } while(0)

#define PASS() \
    do { \
        printf("PASSED\n"); \
        tests_passed++; \
    } while(0)

#define FAIL(msg) \
    do { \
        printf("FAILED: %s\n", msg); \
        tests_failed++; \
    } while(0)

// Test base64 encoding
static void test_base64_encode() {
    TEST(test_base64_encode);

    // Basic test
    const unsigned char* in1 = (const unsigned char*)"foobar";
    char* out1 = cwebsocket_base64_encode(in1, 6);
    assert(out1 != NULL);
    if(strcmp(out1, "Zm9vYmFy") != 0) {
        FAIL("base64 encoding mismatch");
        free(out1);
        return;
    }
    free(out1);

    // Empty string - returns NULL for 0 length (expected behavior)
    const unsigned char* in2 = (const unsigned char*)"";
    char* out2 = cwebsocket_base64_encode(in2, 0);
    if(out2 != NULL) {
        free(out2);
    }

    // Single character
    const unsigned char* in3 = (const unsigned char*)"a";
    char* out3 = cwebsocket_base64_encode(in3, 1);
    assert(out3 != NULL);
    if(strcmp(out3, "YQ==") != 0) {
        FAIL("single char base64 encoding mismatch");
        free(out3);
        return;
    }
    free(out3);

    // Two characters
    const unsigned char* in4 = (const unsigned char*)"ab";
    char* out4 = cwebsocket_base64_encode(in4, 2);
    assert(out4 != NULL);
    if(strcmp(out4, "YWI=") != 0) {
        FAIL("two char base64 encoding mismatch");
        free(out4);
        return;
    }
    free(out4);

    PASS();
}

// Test accept key generation
static void test_accept_key() {
    TEST(test_accept_key);

    // RFC 6455 example
    const char* seckey1 = "dGhlIHNhbXBsZSBub25jZQ==";
    char* accept1 = cwebsocket_create_key_challenge_response(seckey1);
    assert(accept1 != NULL);
    if(strcmp(accept1, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != 0) {
        FAIL("accept key mismatch");
        free(accept1);
        return;
    }
    free(accept1);

    // Another test case
    const char* seckey2 = "x3JJHMbDL1EzLkh9GBhXDw==";
    char* accept2 = cwebsocket_create_key_challenge_response(seckey2);
    assert(accept2 != NULL);
    if(strcmp(accept2, "HSmrc0sMlYUkAGmm5OPpG2HaGWk=") != 0) {
        FAIL("second accept key mismatch");
        free(accept2);
        return;
    }
    free(accept2);

    PASS();
}

// Test UTF-8 validation
static void test_utf8_validation() {
    TEST(test_utf8_validation);

    // Valid ASCII
    uint8_t valid_ascii[] = "hello world";
    size_t count = 0;
    int rc = utf8_count_code_points(valid_ascii, &count);
    if(rc != 0 || count != 11) {
        FAIL("valid ASCII failed");
        return;
    }

    // Valid UTF-8 with multi-byte characters
    uint8_t valid_utf8[] = "Hello, 世界"; // "Hello, world" in Japanese
    count = 0;
    rc = utf8_count_code_points(valid_utf8, &count);
    if(rc != 0 || count != 9) { // 7 ASCII + 2 Chinese chars
        FAIL("valid UTF-8 multi-byte failed");
        return;
    }

    // Empty string
    uint8_t empty[] = "";
    count = 0;
    rc = utf8_count_code_points(empty, &count);
    if(rc != 0 || count != 0) {
        FAIL("empty string failed");
        return;
    }

    // Invalid sequence: 0xC3 0x28
    uint8_t invalid1[] = {0xC3, 0x28, 0x00};
    count = 0;
    rc = utf8_count_code_points(invalid1, &count);
    if(rc == 0) {
        FAIL("invalid sequence 1 not detected");
        return;
    }

    // Invalid sequence: continuation byte without lead byte
    uint8_t invalid2[] = {0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(invalid2, &count);
    if(rc == 0) {
        FAIL("invalid sequence 2 not detected");
        return;
    }

    // Overlong encoding (security issue)
    uint8_t overlong[] = {0xC0, 0x80, 0x00}; // Overlong encoding of NULL
    count = 0;
    rc = utf8_count_code_points(overlong, &count);
    if(rc == 0) {
        FAIL("overlong encoding not detected");
        return;
    }

    PASS();
}

// Test URI parsing for ws:// URLs
static void test_uri_parsing_ws() {
    TEST(test_uri_parsing_ws);

    // Flawfinder: ignore - char arrays used with bounds-checked parse_uri function
    char hostname[100], port[6], resource[256], querystring[256];
    cwebsocket_client websocket;
    memset(&websocket, 0, sizeof(websocket));

    // Basic ws:// URL with all components
    cwebsocket_client_parse_uri(&websocket, "ws://example.com:8080/path?query=value",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "example.com") != 0 || strcmp(port, "8080") != 0 ||
       strcmp(resource, "/path") != 0 || strcmp(querystring, "?query=value") != 0) {
        FAIL("full ws:// URL parsing failed");
        return;
    }

    // ws:// URL without port (should default to 80)
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "ws://example.com/path",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "example.com") != 0 || strcmp(port, "80") != 0 ||
       strcmp(resource, "/path") != 0) {
        FAIL("ws:// URL without port failed");
        return;
    }

    // ws:// URL with just hostname
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "ws://example.com",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "example.com") != 0 || strcmp(port, "80") != 0 ||
       strcmp(resource, "/") != 0) {
        FAIL("ws:// URL with just hostname failed");
        return;
    }

    PASS();
}

// Test URI parsing for wss:// URLs
static void test_uri_parsing_wss() {
    TEST(test_uri_parsing_wss);

#ifdef ENABLE_SSL
    // Flawfinder: ignore - char arrays used with bounds-checked parse_uri function
    char hostname[100], port[6], resource[256], querystring[256];
    cwebsocket_client websocket;
    memset(&websocket, 0, sizeof(websocket));

    // Basic wss:// URL with all components
    cwebsocket_client_parse_uri(&websocket, "wss://secure.example.com:8443/path?query=value",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "secure.example.com") != 0 || strcmp(port, "8443") != 0 ||
       strcmp(resource, "/path") != 0 || strcmp(querystring, "?query=value") != 0 ||
       !(websocket.flags & WEBSOCKET_FLAG_SSL)) {
        FAIL("full wss:// URL parsing failed");
        return;
    }

    // wss:// URL without port (should default to 443)
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "wss://secure.example.com/path",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "secure.example.com") != 0 || strcmp(port, "443") != 0 ||
       strcmp(resource, "/path") != 0 || !(websocket.flags & WEBSOCKET_FLAG_SSL)) {
        FAIL("wss:// URL without port failed");
        return;
    }

    // wss:// URL with just hostname
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "wss://secure.example.com",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "secure.example.com") != 0 || strcmp(port, "443") != 0 ||
       strcmp(resource, "/") != 0 || !(websocket.flags & WEBSOCKET_FLAG_SSL)) {
        FAIL("wss:// URL with just hostname failed");
        return;
    }
#else
    printf("SKIPPED (SSL not enabled)\n");
    return;
#endif

    PASS();
}

// Test client initialization
static void test_client_init() {
    TEST(test_client_init);

    cwebsocket_client *websocket = (cwebsocket_client *)malloc(sizeof(cwebsocket_client) + sizeof(cwebsocket_subprotocol *));
    if(websocket == NULL) {
        FAIL("malloc failed");
        return;
    }

    cwebsocket_client_init(websocket, NULL, 0);

    // Check initial state
    if(websocket->fd != 0 || websocket->retry != 0 ||
       websocket->flags != 0 || websocket->state != WEBSOCKET_STATE_CLOSED ||
       websocket->fragment_buffer != NULL || websocket->fragment_length != 0 ||
       websocket->fragment_capacity != 0 || websocket->close_sent != 0 ||
       websocket->close_received != 0 || websocket->protocol_error != 0) {
        FAIL("initial state incorrect");
        free(websocket);
        return;
    }

    // Check default window bits
    if(websocket->pmdeflate_client_window_bits != 15 ||
       websocket->pmdeflate_server_window_bits != 15) {
        FAIL("default window bits incorrect");
        free(websocket);
        return;
    }

    free(websocket);
    PASS();
}

// Test masking key generation
static void test_masking_key_generation() {
    TEST(test_masking_key_generation);

    uint8_t key1[4] = {0};
    uint8_t key2[4] = {0};

    cwebsocket_client_create_masking_key(key1);
    cwebsocket_client_create_masking_key(key2);

    // Keys should not be all zeros (statistically very unlikely)
    int all_zero1 = (key1[0] == 0 && key1[1] == 0 && key1[2] == 0 && key1[3] == 0);
    int all_zero2 = (key2[0] == 0 && key2[1] == 0 && key2[2] == 0 && key2[3] == 0);

    if(all_zero1 && all_zero2) {
        FAIL("masking keys are all zeros");
        return;
    }

    // Keys should be different (statistically very likely)
    // Note: This test has a very small probability of failing even with correct implementation
    int same = (memcmp(key1, key2, 4) == 0);
    if(same) {
        printf("WARNING: Generated identical masking keys (very unlikely but possible)\n");
    }

    PASS();
}

// Test frame printing (just ensure it doesn't crash)
static void test_frame_print() {
    TEST(test_frame_print);

    cwebsocket_frame frame;
    memset(&frame, 0, sizeof(frame));
    frame.fin = 1;
    frame.rsv1 = 0;
    frame.rsv2 = 0;
    frame.rsv3 = 0;
    frame.opcode = TEXT_FRAME;
    frame.mask = 1;
    frame.payload_len = 125;

    // This should not crash
    cwebsocket_print_frame(&frame);

    PASS();
}

// Test WebSocket states
static void test_websocket_states() {
    TEST(test_websocket_states);

    // Verify state constants are distinct
    if(WEBSOCKET_STATE_CONNECTING == WEBSOCKET_STATE_CONNECTED ||
       WEBSOCKET_STATE_CONNECTING == WEBSOCKET_STATE_OPEN ||
       WEBSOCKET_STATE_CONNECTING == WEBSOCKET_STATE_CLOSING ||
       WEBSOCKET_STATE_CONNECTING == WEBSOCKET_STATE_CLOSED) {
        FAIL("state constants overlap");
        return;
    }

    // Verify states are powers of 2 (bit flags)
    if((WEBSOCKET_STATE_CONNECTING & (WEBSOCKET_STATE_CONNECTING - 1)) != 0 ||
       (WEBSOCKET_STATE_CONNECTED & (WEBSOCKET_STATE_CONNECTED - 1)) != 0 ||
       (WEBSOCKET_STATE_OPEN & (WEBSOCKET_STATE_OPEN - 1)) != 0 ||
       (WEBSOCKET_STATE_CLOSING & (WEBSOCKET_STATE_CLOSING - 1)) != 0 ||
       (WEBSOCKET_STATE_CLOSED & (WEBSOCKET_STATE_CLOSED - 1)) != 0) {
        FAIL("states are not powers of 2");
        return;
    }

    PASS();
}

// Test opcodes
static void test_opcodes() {
    TEST(test_opcodes);

    // Verify opcodes match RFC 6455
    if(CONTINUATION != 0x00 || TEXT_FRAME != 0x01 || BINARY_FRAME != 0x02 ||
       CLOSE != 0x08 || PING != 0x09 || PONG != 0x0A) {
        FAIL("opcode values incorrect");
        return;
    }

    PASS();
}

// Test buffer size constants
static void test_buffer_constants() {
    TEST(test_buffer_constants);

    // Verify buffer sizes are reasonable
    if(CWS_HANDSHAKE_BUFFER_MAX < 1024) {
        FAIL("handshake buffer too small");
        return;
    }

    if(CWS_DATA_BUFFER_MAX < 65536) {
        FAIL("data buffer too small");
        return;
    }

    PASS();
}

// Test multiple base64 encoding edge cases
static void test_base64_edge_cases() {
    TEST(test_base64_edge_cases);

    // Test with binary data (not just text)
    uint8_t binary[256];
    for(int i = 0; i < 256; i++) {
        binary[i] = (uint8_t)i;
    }
    char* encoded = cwebsocket_base64_encode(binary, 256);
    assert(encoded != NULL);
    // Just verify it doesn't crash and returns something
    // Flawfinder: ignore - strlen on null-terminated encoded string
    if(strlen(encoded) == 0) {
        FAIL("binary encoding returned empty string");
        free(encoded);
        return;
    }
    free(encoded);

    // Test with all zeros
    uint8_t zeros[16] = {0};
    char* encoded_zeros = cwebsocket_base64_encode(zeros, 16);
    assert(encoded_zeros != NULL);
    if(strcmp(encoded_zeros, "AAAAAAAAAAAAAAAAAAAAAA==") != 0) {
        FAIL("all zeros encoding incorrect");
        free(encoded_zeros);
        return;
    }
    free(encoded_zeros);

    // Test with all 0xFF
    uint8_t ones[16];
    memset(ones, 0xFF, 16);
    char* encoded_ones = cwebsocket_base64_encode(ones, 16);
    assert(encoded_ones != NULL);
    if(strcmp(encoded_ones, "/////////////////////w==") != 0) {
        FAIL("all 0xFF encoding incorrect");
        free(encoded_ones);
        return;
    }
    free(encoded_ones);

    PASS();
}

// Test close code validation (RFC 6455)
static void test_close_code_validation() {
    TEST(test_close_code_validation);

    // Standard valid codes
    if(!cwebsocket_is_valid_close_code(1000)) { // Normal closure
        FAIL("1000 should be valid");
        return;
    }
    if(!cwebsocket_is_valid_close_code(1001)) { // Going away
        FAIL("1001 should be valid");
        return;
    }
    if(!cwebsocket_is_valid_close_code(1002)) { // Protocol error
        FAIL("1002 should be valid");
        return;
    }
    if(!cwebsocket_is_valid_close_code(1003)) { // Unsupported data
        FAIL("1003 should be valid");
        return;
    }

    // Reserved codes (invalid)
    if(cwebsocket_is_valid_close_code(1004)) { // Reserved
        FAIL("1004 should be invalid");
        return;
    }
    if(cwebsocket_is_valid_close_code(1005)) { // No status received
        FAIL("1005 should be invalid");
        return;
    }
    if(cwebsocket_is_valid_close_code(1006)) { // Abnormal closure
        FAIL("1006 should be invalid");
        return;
    }
    if(cwebsocket_is_valid_close_code(1015)) { // TLS handshake
        FAIL("1015 should be invalid");
        return;
    }

    // Application codes (valid)
    if(!cwebsocket_is_valid_close_code(3000)) { // Library/framework code
        FAIL("3000 should be valid");
        return;
    }
    if(!cwebsocket_is_valid_close_code(4000)) { // Application code
        FAIL("4000 should be valid");
        return;
    }

    // Out of range (invalid)
    if(cwebsocket_is_valid_close_code(999)) {
        FAIL("999 should be invalid");
        return;
    }
    if(cwebsocket_is_valid_close_code(5000)) {
        FAIL("5000 should be invalid");
        return;
    }

    PASS();
}

// Test control frame detection
static void test_control_frame_detection() {
    TEST(test_control_frame_detection);

    // Control frames
    if(!cwebsocket_client_is_control_frame(CLOSE)) {
        FAIL("CLOSE should be control frame");
        return;
    }
    if(!cwebsocket_client_is_control_frame(PING)) {
        FAIL("PING should be control frame");
        return;
    }
    if(!cwebsocket_client_is_control_frame(PONG)) {
        FAIL("PONG should be control frame");
        return;
    }

    // Data frames (not control)
    if(cwebsocket_client_is_control_frame(TEXT_FRAME)) {
        FAIL("TEXT_FRAME should not be control frame");
        return;
    }
    if(cwebsocket_client_is_control_frame(BINARY_FRAME)) {
        FAIL("BINARY_FRAME should not be control frame");
        return;
    }
    if(cwebsocket_client_is_control_frame(CONTINUATION)) {
        FAIL("CONTINUATION should not be control frame");
        return;
    }

    PASS();
}

// Test HTTP header token parsing
static void test_header_token_parsing() {
    TEST(test_header_token_parsing);

    // Single token
    if(!cwebsocket_header_contains_token("upgrade", "upgrade")) {
        FAIL("should find 'upgrade' in 'upgrade'");
        return;
    }

    // Multiple tokens
    if(!cwebsocket_header_contains_token("keep-alive, upgrade", "upgrade")) {
        FAIL("should find 'upgrade' in comma-separated list");
        return;
    }

    // Case insensitive
    if(!cwebsocket_header_contains_token("Keep-Alive, Upgrade", "upgrade")) {
        FAIL("should be case insensitive");
        return;
    }

    // With whitespace
    if(!cwebsocket_header_contains_token("  keep-alive , upgrade  ", "upgrade")) {
        FAIL("should handle whitespace");
        return;
    }

    // Token not present
    if(cwebsocket_header_contains_token("keep-alive", "upgrade")) {
        FAIL("should not find missing token");
        return;
    }

    // Empty header
    if(cwebsocket_header_contains_token("", "upgrade")) {
        FAIL("should not find token in empty header");
        return;
    }

    PASS();
}

// Test string trimming
static void test_string_trim() {
    TEST(test_string_trim);

    // Leading whitespace
    char test1[] = "  hello";
    cwebsocket_trim(test1);
    if(strcmp(test1, "hello") != 0) {
        FAIL("should trim leading whitespace");
        return;
    }

    // Trailing whitespace
    char test2[] = "hello  ";
    cwebsocket_trim(test2);
    if(strcmp(test2, "hello") != 0) {
        FAIL("should trim trailing whitespace");
        return;
    }

    // Both
    char test3[] = "  hello  ";
    cwebsocket_trim(test3);
    if(strcmp(test3, "hello") != 0) {
        FAIL("should trim both sides");
        return;
    }

    // Tabs and spaces
    char test4[] = "\t hello \t";
    cwebsocket_trim(test4);
    if(strcmp(test4, "hello") != 0) {
        FAIL("should trim tabs and spaces");
        return;
    }

    // No whitespace
    char test5[] = "hello";
    cwebsocket_trim(test5);
    if(strcmp(test5, "hello") != 0) {
        FAIL("should handle no whitespace");
        return;
    }

    // Empty string
    char test6[] = "";
    cwebsocket_trim(test6);
    if(strcmp(test6, "") != 0) {
        FAIL("should handle empty string");
        return;
    }

    // Only whitespace
    char test7[] = "   ";
    cwebsocket_trim(test7);
    if(strcmp(test7, "") != 0) {
        FAIL("should handle only whitespace");
        return;
    }

    PASS();
}

// Test fragment buffer management
static void test_fragment_management() {
    TEST(test_fragment_management);

    cwebsocket_client *websocket = (cwebsocket_client *)calloc(1, sizeof(cwebsocket_client) + sizeof(cwebsocket_subprotocol *));
    if(websocket == NULL) {
        FAIL("malloc failed");
        return;
    }

    cwebsocket_client_init(websocket, NULL, 0);

    // Initially no buffer
    if(websocket->fragment_buffer != NULL) {
        FAIL("fragment buffer should be NULL initially");
        free(websocket);
        return;
    }

    // Allocate small buffer
    if(cwebsocket_client_ensure_fragment_capacity(websocket, 100) != 0) {
        FAIL("should allocate fragment buffer");
        free(websocket);
        return;
    }
    if(websocket->fragment_capacity < 100) {
        FAIL("fragment capacity should be at least 100");
        free(websocket->fragment_buffer);
        free(websocket);
        return;
    }

    // Expand buffer
    if(cwebsocket_client_ensure_fragment_capacity(websocket, 1000) != 0) {
        FAIL("should expand fragment buffer");
        free(websocket->fragment_buffer);
        free(websocket);
        return;
    }
    if(websocket->fragment_capacity < 1000) {
        FAIL("fragment capacity should be at least 1000");
        free(websocket->fragment_buffer);
        free(websocket);
        return;
    }

    // Request smaller size (should not shrink)
    size_t old_capacity = websocket->fragment_capacity;
    if(cwebsocket_client_ensure_fragment_capacity(websocket, 500) != 0) {
        FAIL("should succeed for smaller request");
        free(websocket->fragment_buffer);
        free(websocket);
        return;
    }
    if(websocket->fragment_capacity != old_capacity) {
        FAIL("should not shrink buffer");
        free(websocket->fragment_buffer);
        free(websocket);
        return;
    }

    // Reset fragments
    websocket->fragment_length = 123;
    websocket->fragment_in_progress = 1;
    cwebsocket_client_reset_fragments(websocket);
    if(websocket->fragment_length != 0 || websocket->fragment_in_progress != 0) {
        FAIL("should reset fragment state");
        free(websocket->fragment_buffer);
        free(websocket);
        return;
    }

    free(websocket->fragment_buffer);
    free(websocket);
    PASS();
}

// Test client initialization with subprotocols
static void test_client_init_with_subprotocols() {
    TEST(test_client_init_with_subprotocols);

    // Create mock subprotocols
    cwebsocket_subprotocol proto1 = {
        .name = "echo",
        .onopen = NULL,
        .onmessage = NULL,
        .onclose = NULL,
        .onerror = NULL
    };

    cwebsocket_subprotocol proto2 = {
        .name = "chat",
        .onopen = NULL,
        .onmessage = NULL,
        .onclose = NULL,
        .onerror = NULL
    };

    cwebsocket_subprotocol *protos[] = {&proto1, &proto2};

    cwebsocket_client *websocket = (cwebsocket_client *)calloc(1, sizeof(cwebsocket_client) + 2 * sizeof(cwebsocket_subprotocol *));
    if(websocket == NULL) {
        FAIL("malloc failed");
        return;
    }

    cwebsocket_client_init(websocket, protos, 2);

    // Check subprotocols were stored
    if(websocket->subprotocol_len != 2) {
        FAIL("subprotocol_len should be 2");
        free(websocket);
        return;
    }

    if(websocket->subprotocols[0] != &proto1) {
        FAIL("subprotocols[0] should be proto1");
        free(websocket);
        return;
    }

    if(websocket->subprotocols[1] != &proto2) {
        FAIL("subprotocols[1] should be proto2");
        free(websocket);
        return;
    }

    free(websocket);
    PASS();
}

// Test random bytes generation
static void test_random_bytes() {
    TEST(test_random_bytes);

    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));

    if(cwebsocket_client_random_bytes(buf, sizeof(buf)) != 0) {
        FAIL("should generate random bytes");
        return;
    }

    // Check that not all bytes are zero (statistically very unlikely)
    int all_zero = 1;
    for(size_t i = 0; i < sizeof(buf); i++) {
        if(buf[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if(all_zero) {
        FAIL("random bytes should not all be zero");
        return;
    }

    PASS();
}

// Test callback functions (just ensure they don't crash)
static int callback_invoked = 0;

static void mock_onopen(void *arg) {
    callback_invoked++;
}

static void mock_onmessage(void *arg, cwebsocket_message *message) {
    callback_invoked++;
}

static void mock_onclose(void *arg, int code, const char *message) {
    callback_invoked++;
}

static void mock_onerror(void *arg, const char *error) {
    callback_invoked++;
}

static void test_event_callbacks() {
    TEST(test_event_callbacks);

    cwebsocket_subprotocol proto = {
        .name = "test",
        .onopen = mock_onopen,
        .onmessage = mock_onmessage,
        .onclose = mock_onclose,
        .onerror = mock_onerror
    };

    cwebsocket_subprotocol *protos[] = {&proto};
    cwebsocket_client *websocket = (cwebsocket_client *)calloc(1, sizeof(cwebsocket_client) + sizeof(cwebsocket_subprotocol *));
    if(websocket == NULL) {
        FAIL("malloc failed");
        return;
    }

    cwebsocket_client_init(websocket, protos, 1);
    websocket->subprotocol = &proto;

    callback_invoked = 0;

    // Test onopen
    cwebsocket_client_onopen(websocket);
    if(callback_invoked != 1) {
        FAIL("onopen callback not invoked");
        free(websocket);
        return;
    }

    // Test onmessage
    cwebsocket_message msg = {.opcode = TEXT_FRAME, .payload_len = 4, .payload = "test"};
    cwebsocket_client_onmessage(websocket, &msg);
    if(callback_invoked != 2) {
        FAIL("onmessage callback not invoked");
        free(websocket);
        return;
    }

    // Test onclose
    cwebsocket_client_onclose(websocket, 1000, "normal");
    if(callback_invoked != 3) {
        FAIL("onclose callback not invoked");
        free(websocket);
        return;
    }

    // Test onerror
    cwebsocket_client_onerror(websocket, "test error");
    if(callback_invoked != 4) {
        FAIL("onerror callback not invoked");
        free(websocket);
        return;
    }

    free(websocket);
    PASS();
}

// Test URI parsing edge cases
static void test_uri_parsing_edge_cases() {
    TEST(test_uri_parsing_edge_cases);

    // Flawfinder: ignore - char arrays used with bounds-checked parse_uri function
    char hostname[100], port[6], resource[256], querystring[256];
    cwebsocket_client websocket;

    // ws:// with port and no resource
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "ws://example.com:8080",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "example.com") != 0 || strcmp(port, "8080") != 0 ||
       strcmp(resource, "/") != 0 || strcmp(querystring, "") != 0) {
        FAIL("ws:// with port and no resource failed");
        return;
    }

#ifdef ENABLE_SSL
    // wss:// with port and resource
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "wss://example.com:8443/resource",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "example.com") != 0 || strcmp(port, "8443") != 0 ||
       strcmp(resource, "/resource") != 0 || strcmp(querystring, "") != 0 ||
       !(websocket.flags & WEBSOCKET_FLAG_SSL)) {
        FAIL("wss:// with port and resource failed");
        return;
    }
#endif

    PASS();
}

// Test additional close code edge cases
static void test_close_code_edge_cases() {
    TEST(test_close_code_edge_cases);

    // Test boundary values
    if(cwebsocket_is_valid_close_code(1000)) {
        // 1000 is valid (normal closure)
    } else {
        FAIL("1000 should be valid close code");
        return;
    }

    if(cwebsocket_is_valid_close_code(1001)) {
        // 1001 is valid (going away)
    } else {
        FAIL("1001 should be valid close code");
        return;
    }

    if(cwebsocket_is_valid_close_code(1011)) {
        // 1011 is valid (internal server error)
    } else {
        FAIL("1011 should be valid close code");
        return;
    }

    // Test reserved ranges - 1004, 1005, 1006, 1015 are invalid for sending
    if(!cwebsocket_is_valid_close_code(1004)) {
        // 1004 is reserved
    } else {
        FAIL("1004 should be invalid (reserved)");
        return;
    }

    if(!cwebsocket_is_valid_close_code(1005)) {
        // 1005 is reserved (no status received)
    } else {
        FAIL("1005 should be invalid (reserved)");
        return;
    }

    if(!cwebsocket_is_valid_close_code(1006)) {
        // 1006 is reserved (abnormal closure)
    } else {
        FAIL("1006 should be invalid (reserved)");
        return;
    }

    if(!cwebsocket_is_valid_close_code(1015)) {
        // 1015 is reserved (TLS handshake failure)
    } else {
        FAIL("1015 should be invalid (reserved)");
        return;
    }

    // Test values outside valid range
    if(!cwebsocket_is_valid_close_code(999)) {
        // Below 1000 is invalid
    } else {
        FAIL("999 should be invalid");
        return;
    }

    if(!cwebsocket_is_valid_close_code(5000)) {
        // Above 4999 is invalid
    } else {
        FAIL("5000 should be invalid");
        return;
    }

    PASS();
}

// Test URI parsing error cases
static void test_uri_parsing_error_cases() {
    TEST(test_uri_parsing_error_cases);

    // Flawfinder: ignore - char arrays used with bounds-checked parse_uri function
    char hostname[100], port[6], resource[256], querystring[256];
    cwebsocket_client websocket;

    // Test with minimal URL
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "ws://localhost",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "localhost") != 0 || strcmp(port, "80") != 0) {
        FAIL("minimal URL parsing failed");
        return;
    }

    // Test with IP address
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "ws://127.0.0.1:9000/path",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "127.0.0.1") != 0 || strcmp(port, "9000") != 0 ||
       strcmp(resource, "/path") != 0) {
        FAIL("IP address URL parsing failed");
        return;
    }

    // Test with complex query string (with port)
    memset(&websocket, 0, sizeof(websocket));
    memset(hostname, 0, sizeof(hostname));
    memset(port, 0, sizeof(port));
    memset(resource, 0, sizeof(resource));
    memset(querystring, 0, sizeof(querystring));
    cwebsocket_client_parse_uri(&websocket, "ws://test.com:8080/api?key=value&foo=bar",
                                hostname, port, resource, querystring);
    if(strcmp(hostname, "test.com") != 0 || strcmp(port, "8080") != 0 ||
       strcmp(resource, "/api") != 0 || strcmp(querystring, "?key=value&foo=bar") != 0) {
        FAIL("complex query string parsing failed");
        return;
    }

    PASS();
}

// Test client state management
static void test_client_state_management() {
    TEST(test_client_state_management);

    cwebsocket_client *client = (cwebsocket_client *)calloc(1, sizeof(cwebsocket_client));
    if(client == NULL) {
        FAIL("client allocation failed");
        return;
    }

    cwebsocket_client_init(client, NULL, 0);

    // Check initial state
    if(client->state != WEBSOCKET_STATE_CLOSED) {
        FAIL("initial state should be CLOSED");
        free(client);
        return;
    }

    // Verify initial flags
    if(client->protocol_error != 0) {
        FAIL("initial protocol_error should be 0");
        free(client);
        return;
    }

    // Verify buffer initialization
    if(client->fragment_buffer != NULL) {
        FAIL("fragment_buffer should be NULL initially");
        free(client);
        return;
    }

    if(client->fragment_length != 0) {
        FAIL("fragment_length should be 0 initially");
        free(client);
        return;
    }

    if(client->fragment_capacity != 0) {
        FAIL("fragment_capacity should be 0 initially");
        free(client);
        return;
    }

    free(client);
    PASS();
}

// Test subprotocol matching
static void test_subprotocol_matching() {
    TEST(test_subprotocol_matching);

    // Create mock subprotocols
    cwebsocket_subprotocol proto1 = {
        .name = "chat",
        .onopen = NULL,
        .onmessage = NULL,
        .onclose = NULL,
        .onerror = NULL
    };

    cwebsocket_subprotocol proto2 = {
        .name = "superchat",
        .onopen = NULL,
        .onmessage = NULL,
        .onclose = NULL,
        .onerror = NULL
    };

    cwebsocket_subprotocol *protos[] = {&proto1, &proto2};

    cwebsocket_client *client = (cwebsocket_client *)calloc(1, sizeof(cwebsocket_client) + 2 * sizeof(cwebsocket_subprotocol *));
    if(client == NULL) {
        FAIL("client allocation failed");
        return;
    }

    cwebsocket_client_init(client, protos, 2);

    // Verify subprotocols were set
    if(client->subprotocol_len != 2) {
        FAIL("should have 2 subprotocols");
        free(client);
        return;
    }

    // Verify the protocol pointers are correct
    if(client->subprotocols[0] != &proto1) {
        FAIL("subprotocols[0] should be proto1");
        free(client);
        return;
    }

    if(client->subprotocols[1] != &proto2) {
        FAIL("subprotocols[1] should be proto2");
        free(client);
        return;
    }

    // Verify the names
    if(strcmp(client->subprotocols[0]->name, "chat") != 0) {
        FAIL("subprotocols[0] name should be 'chat'");
        free(client);
        return;
    }

    if(strcmp(client->subprotocols[1]->name, "superchat") != 0) {
        FAIL("subprotocols[1] name should be 'superchat'");
        free(client);
        return;
    }

    free(client);
    PASS();
}

// Test header parsing edge cases
static void test_header_parsing_edge_cases() {
    TEST(test_header_parsing_edge_cases);

    // Test case-insensitive matching
    if(!cwebsocket_header_contains_token("Upgrade", "upgrade")) {
        FAIL("case-insensitive match failed");
        return;
    }

    if(!cwebsocket_header_contains_token("UPGRADE", "upgrade")) {
        FAIL("uppercase header match failed");
        return;
    }

    // Test with extra whitespace
    if(!cwebsocket_header_contains_token("  websocket  ", "websocket")) {
        FAIL("whitespace handling failed");
        return;
    }

    // Test comma-separated values
    if(!cwebsocket_header_contains_token("keep-alive, Upgrade", "upgrade")) {
        FAIL("comma-separated token match failed");
        return;
    }

    // Test non-match
    if(cwebsocket_header_contains_token("websocket", "http")) {
        FAIL("should not match different token");
        return;
    }

    // Test empty strings
    if(cwebsocket_header_contains_token("", "websocket")) {
        FAIL("empty header should not match");
        return;
    }

    PASS();
}

// Run all tests
int main(void) {
    printf("=== cwebsocket Comprehensive Unit Tests ===\n\n");

    // Core functionality tests
    test_base64_encode();
    test_base64_edge_cases();
    test_accept_key();
    test_utf8_validation();

    // URI parsing tests
    test_uri_parsing_ws();
    test_uri_parsing_wss();
    test_uri_parsing_edge_cases();

    // Client tests
    test_client_init();
    test_client_init_with_subprotocols();
    test_masking_key_generation();
    test_random_bytes();

    // Fragment management
    test_fragment_management();

    // Frame and protocol tests
    test_frame_print();
    test_websocket_states();
    test_opcodes();
    test_buffer_constants();
    test_close_code_validation();
    test_control_frame_detection();

    // String/header parsing
    test_header_token_parsing();
    test_string_trim();

    // Event callbacks
    test_event_callbacks();

    // Additional coverage tests
    test_close_code_edge_cases();
    test_uri_parsing_error_cases();
    test_client_state_management();
    test_subprotocol_matching();
    test_header_parsing_edge_cases();

    // Summary
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n", tests_passed + tests_failed);

    if(tests_failed == 0) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed!\n");
        return 1;
    }
}
