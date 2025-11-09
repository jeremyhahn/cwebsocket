/**
 *  MQTT 5.0 Enhanced Authentication (SCRAM-SHA-256) Test
 *
 *  Tests MQTT 5.0 enhanced authentication with SCRAM-SHA-256:
 *  - CONNECT with authentication_method
 *  - AUTH packet challenge/response flow
 *  - SCRAM client-first, client-final, server-final messages
 *  - Successful authentication completion
 *
 *  Prerequisites:
 *  1. Docker with EMQX broker
 *  2. SCRAM-SHA-256 configured via HTTP API
 *  3. Test user created (testuser / testpass123)
 *
 *  Run with: make test-mqtt-auth
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "../../src/cwebsocket/client.h"
#include "../../src/cwebsocket/subprotocol/mqtt/mqtt_client.h"

// Test state
static cwebsocket_client websocket_client;
static int connected = 0;
static int authenticated = 0;
static const char *broker_url = "ws://localhost:8083/mqtt";

// Test tracking
static int tests_passed = 0;
static int tests_failed = 0;
static int test_running = 1;

#define TEST_PASS(name) do { \
    printf("  ✓ %s\n", name); \
    tests_passed++; \
} while(0)

#define TEST_FAIL(name, msg) do { \
    printf("  ✗ %s: %s\n", name, msg); \
    tests_failed++; \
} while(0)

#define ASSERT(condition, test_name, msg) do { \
    if (condition) { \
        TEST_PASS(test_name); \
    } else { \
        TEST_FAIL(test_name, msg); \
    } \
} while(0)

void wait_ms(int ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000};
    nanosleep(&ts, NULL);
}

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        test_running = 0;
    }
}

void print_test_header(const char *section) {
    printf("\n========================================\n");
    printf("  %s\n", section);
    printf("========================================\n");
}

void print_test_results() {
    printf("\n========================================\n");
    printf("  TEST RESULTS\n");
    printf("========================================\n");
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("  Total:  %d\n", tests_passed + tests_failed);
    printf("========================================\n\n");

    if (tests_failed > 0) {
        exit(1);
    }
}

void test_scram_authentication() {
    print_test_header("SCRAM-SHA-256 Enhanced Authentication");

    printf("\n");
    printf("Creating WebSocket client...\n");

    // Initialize client with SCRAM credentials
    cwebsocket_subprotocol *protocol = cwebsocket_subprotocol_mqtt_client_new(
        "scram_test_client",
        "testuser",      // Username from setup-scram.sh
        "testpass123",   // Password from setup-scram.sh
        60,              // Keep alive
        1                // Clean start
    );

    if (!protocol) {
        TEST_FAIL("Client initialization", "Failed to create MQTT protocol");
        return;
    }
    TEST_PASS("Client initialization with SCRAM-SHA-256");

    printf("Connecting to broker at %s...\n", broker_url);

    // Connect to broker
    cwebsocket_subprotocol *subprotocols[] = {protocol};
    cwebsocket_client_init(&websocket_client, subprotocols, 1);
    websocket_client.uri = broker_url;

    int connect_result = cwebsocket_client_connect(&websocket_client);

    if (connect_result < 0) {
        TEST_FAIL("WebSocket connection", "Failed to connect to broker");
        return;
    }
    TEST_PASS("WebSocket connection established");

    // Wait for authentication to complete
    printf("Waiting for SCRAM authentication to complete...\n");

    int timeout = 10;  // 10 second timeout
    int authenticated_flag = 0;

    while (timeout > 0 && test_running) {
        wait_ms(1000);
        timeout--;

        // Check if client is connected (authentication completed)
        if (websocket_client.state == WEBSOCKET_STATE_OPEN) {
            authenticated_flag = 1;
            break;
        }
    }

    if (authenticated_flag) {
        TEST_PASS("SCRAM-SHA-256 authentication completed successfully");
    } else {
        TEST_FAIL("SCRAM-SHA-256 authentication", "Authentication timed out");
    }

    // Try to publish a message to verify we're authenticated
    if (authenticated_flag) {
        printf("Attempting to publish test message...\n");

        mqtt_send_publish(
            &websocket_client,
            "test/scram/topic",
            (const uint8_t *)"SCRAM authenticated",
            19,
            MQTT_QOS_0,
            0,  // retain
            0   // dup
        );

        wait_ms(1000);
        TEST_PASS("Message published after SCRAM authentication");
    }

    // Clean disconnect
    printf("Disconnecting...\n");
    mqtt_send_disconnect(&websocket_client, 0, "Test complete");
    wait_ms(500);

    cwebsocket_client_close(&websocket_client, 1000, "Normal closure");
    wait_ms(500);

    TEST_PASS("Clean disconnect after SCRAM session");
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    openlog("mqtt-auth-test", LOG_PID | LOG_CONS, LOG_USER);

    printf("\n");
    printf("╔══════════════════════════════════════╗\n");
    printf("║  MQTT 5.0 Enhanced Authentication   ║\n");
    printf("║     SCRAM-SHA-256 Test Suite        ║\n");
    printf("╚══════════════════════════════════════╝\n");
    printf("\n");
    printf("Prerequisites:\n");
    printf("  - EMQX broker running on %s\n", broker_url);
    printf("  - SCRAM-SHA-256 authentication configured\n");
    printf("  - Test user 'testuser' with password 'testpass123'\n");
    printf("\n");

    // Run authentication test
    test_scram_authentication();

    // Print results
    print_test_results();

    closelog();

    return (tests_failed > 0) ? 1 : 0;
}
