/**
 *  Comprehensive Logging System Test Suite
 *
 *  Copyright 2014 Jeremy Hahn
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "../src/cwebsocket/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <assert.h>

// Test counters
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

// Custom callback test data
static int callback_invoked = 0;
static cwebsocket_log_level callback_last_level = CWEBSOCKET_LOG_LEVEL_NONE;
static char callback_last_message[1024] = "";

#define TEST_START(name) \
    do { \
        printf("\n[TEST] %s\n", name); \
        tests_run++; \
    } while(0)

#define TEST_PASS() \
    do { \
        printf("  [PASS]\n"); \
        tests_passed++; \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        printf("  [FAIL] %s\n", msg); \
        tests_failed++; \
    } while(0)

#define ASSERT(condition, msg) \
    do { \
        if (!(condition)) { \
            TEST_FAIL(msg); \
            return; \
        } \
    } while(0)

// =============================================================================
// Custom Callback for Testing
// =============================================================================

void test_callback(
    cwebsocket_log_level level,
    const char *function,
    const char *file,
    int line,
    const char *format,
    va_list args
) {
    callback_invoked++;
    callback_last_level = level;
    vsnprintf(callback_last_message, sizeof(callback_last_message), format, args);
}

// =============================================================================
// Test Functions
// =============================================================================

void test_initialization(void) {
    TEST_START("Initialization and Shutdown");

    cwebsocket_log_init();

    const cwebsocket_log_config *config = cwebsocket_log_get_config();
    ASSERT(config != NULL, "Config should not be NULL");
    ASSERT(config->level == CWEBSOCKET_LOG_LEVEL_ERROR, "Default level should be ERROR");
    ASSERT(config->backends == CWEBSOCKET_LOG_BACKEND_SYSLOG, "Default backend should be syslog");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_log_levels(void) {
    TEST_START("Log Level Configuration");

    cwebsocket_log_init();

    // Test setting each level
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_DEBUG);
    ASSERT(cwebsocket_log_get_level() == CWEBSOCKET_LOG_LEVEL_DEBUG, "Level should be DEBUG");

    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_TRACE);
    ASSERT(cwebsocket_log_get_level() == CWEBSOCKET_LOG_LEVEL_TRACE, "Level should be TRACE");

    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_NONE);
    ASSERT(cwebsocket_log_get_level() == CWEBSOCKET_LOG_LEVEL_NONE, "Level should be NONE");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_level_string_conversion(void) {
    TEST_START("Log Level String Conversion");

    // Test level to string
    ASSERT(strcmp(cwebsocket_log_level_to_string(CWEBSOCKET_LOG_LEVEL_ERROR), "ERROR") == 0,
           "ERROR level string conversion");
    ASSERT(strcmp(cwebsocket_log_level_to_string(CWEBSOCKET_LOG_LEVEL_WARN), "WARN") == 0,
           "WARN level string conversion");
    ASSERT(strcmp(cwebsocket_log_level_to_string(CWEBSOCKET_LOG_LEVEL_INFO), "INFO") == 0,
           "INFO level string conversion");
    ASSERT(strcmp(cwebsocket_log_level_to_string(CWEBSOCKET_LOG_LEVEL_DEBUG), "DEBUG") == 0,
           "DEBUG level string conversion");
    ASSERT(strcmp(cwebsocket_log_level_to_string(CWEBSOCKET_LOG_LEVEL_TRACE), "TRACE") == 0,
           "TRACE level string conversion");

    // Test string to level
    ASSERT(cwebsocket_log_string_to_level("ERROR") == CWEBSOCKET_LOG_LEVEL_ERROR,
           "String to ERROR level");
    ASSERT(cwebsocket_log_string_to_level("warn") == CWEBSOCKET_LOG_LEVEL_WARN,
           "String to WARN level (case insensitive)");
    ASSERT(cwebsocket_log_string_to_level("INFO") == CWEBSOCKET_LOG_LEVEL_INFO,
           "String to INFO level");
    ASSERT(cwebsocket_log_string_to_level("debug") == CWEBSOCKET_LOG_LEVEL_DEBUG,
           "String to DEBUG level");

    TEST_PASS();
}

void test_backend_configuration(void) {
    TEST_START("Backend Configuration");

    cwebsocket_log_init();

    // Test enabling/disabling stderr backend
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_STDERR, 1);
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_STDERR),
           "STDERR backend should be enabled");

    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_STDERR, 0);
    ASSERT(!cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_STDERR),
           "STDERR backend should be disabled");

    // Test enabling multiple backends
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_SYSLOG, 1);
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_STDERR, 1);
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_SYSLOG),
           "SYSLOG backend should be enabled");
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_STDERR),
           "STDERR backend should be enabled");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_file_backend(void) {
    TEST_START("File Backend");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_INFO);

    const char *test_file = "/tmp/cwebsocket_test.log";
    unlink(test_file);  // Clean up if exists

    // Set file backend
    int result = cwebsocket_log_set_file(test_file);
    ASSERT(result == 0, "File backend should be set successfully");
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_FILE),
           "File backend should be enabled");

    // Write some logs
    CWEBSOCKET_LOG_INFO("Test info message");
    CWEBSOCKET_LOG_ERROR("Test error message");

    cwebsocket_log_flush();

    // Verify file exists
    struct stat st;
    ASSERT(stat(test_file, &st) == 0, "Log file should exist");
    ASSERT(st.st_size > 0, "Log file should have content");

    // Clean up
    cwebsocket_log_set_file(NULL);
    unlink(test_file);

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_log_rotation(void) {
    TEST_START("Log Rotation");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_DEBUG);

    const char *test_file = "/tmp/cwebsocket_rotation_test.log";
    unlink(test_file);

    // Set file with rotation
    cwebsocket_log_set_file(test_file);
    cwebsocket_log_set_rotation(100, 3);  // Rotate after 100 bytes, keep 3 files

    // Write logs to trigger rotation
    for (int i = 0; i < 10; i++) {
        CWEBSOCKET_LOG_INFO("Test message number %d with some extra data", i);
        cwebsocket_log_flush();
    }

    // Verify rotation occurred
    struct stat st;
    char rotated_file[256];
    snprintf(rotated_file, sizeof(rotated_file), "%s.1", test_file);

    int rotation_occurred = (stat(rotated_file, &st) == 0);
    ASSERT(rotation_occurred, "Log rotation should have occurred");

    // Clean up
    cwebsocket_log_set_file(NULL);
    unlink(test_file);
    for (int i = 1; i <= 3; i++) {
        snprintf(rotated_file, sizeof(rotated_file), "%s.%d", test_file, i);
        unlink(rotated_file);
    }

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_custom_callback(void) {
    TEST_START("Custom Callback");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_DEBUG);

    // Reset callback counters
    callback_invoked = 0;
    callback_last_level = CWEBSOCKET_LOG_LEVEL_NONE;
    memset(callback_last_message, 0, sizeof(callback_last_message));

    // Set custom callback
    cwebsocket_log_set_callback(test_callback, NULL);
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_CALLBACK),
           "Callback backend should be enabled");

    // Disable syslog to avoid interference
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_SYSLOG, 0);

    // Trigger callback
    CWEBSOCKET_LOG_ERROR("Test error from callback");

    ASSERT(callback_invoked == 1, "Callback should be invoked once");
    ASSERT(callback_last_level == CWEBSOCKET_LOG_LEVEL_ERROR, "Callback should receive ERROR level");
    ASSERT(strstr(callback_last_message, "Test error from callback") != NULL,
           "Callback should receive correct message");

    // Test callback with different level
    CWEBSOCKET_LOG_WARN("Test warning from callback");
    ASSERT(callback_invoked == 2, "Callback should be invoked twice");
    ASSERT(callback_last_level == CWEBSOCKET_LOG_LEVEL_WARN, "Callback should receive WARN level");

    // Disable callback
    cwebsocket_log_set_callback(NULL, NULL);
    ASSERT(!cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_CALLBACK),
           "Callback backend should be disabled");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_format_options(void) {
    TEST_START("Format Options");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_INFO);

    const char *test_file = "/tmp/cwebsocket_format_test.log";
    unlink(test_file);

    cwebsocket_log_set_file(test_file);

    // Test with all format options enabled
    cwebsocket_log_set_format(1, 1, 1);  // timestamp, level, location
    CWEBSOCKET_LOG_INFO("Test with all format options");
    cwebsocket_log_flush();

    // Test with format options disabled
    cwebsocket_log_set_format(0, 0, 0);  // No timestamp, level, or location
    CWEBSOCKET_LOG_INFO("Test without format options");
    cwebsocket_log_flush();

    // Verify file has content
    struct stat st;
    ASSERT(stat(test_file, &st) == 0, "Log file should exist");
    ASSERT(st.st_size > 0, "Log file should have content");

    cwebsocket_log_set_file(NULL);
    unlink(test_file);

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_log_level_filtering(void) {
    TEST_START("Log Level Filtering");

    cwebsocket_log_init();

    // Reset callback counters
    callback_invoked = 0;

    cwebsocket_log_set_callback(test_callback, NULL);
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_SYSLOG, 0);

    // Set level to WARN - should filter out DEBUG and INFO
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_WARN);

    CWEBSOCKET_LOG_DEBUG("This should be filtered");
    ASSERT(callback_invoked == 0, "DEBUG message should be filtered when level is WARN");

    CWEBSOCKET_LOG_INFO("This should also be filtered");
    ASSERT(callback_invoked == 0, "INFO message should be filtered when level is WARN");

    CWEBSOCKET_LOG_WARN("This should pass");
    ASSERT(callback_invoked == 1, "WARN message should pass when level is WARN");

    CWEBSOCKET_LOG_ERROR("This should also pass");
    ASSERT(callback_invoked == 2, "ERROR message should pass when level is WARN");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_multiple_backends_simultaneously(void) {
    TEST_START("Multiple Backends Simultaneously");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_INFO);

    const char *test_file = "/tmp/cwebsocket_multi_test.log";
    unlink(test_file);

    // Enable all backends
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_SYSLOG, 1);
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_STDERR, 1);
    cwebsocket_log_set_file(test_file);

    callback_invoked = 0;
    cwebsocket_log_set_callback(test_callback, NULL);

    // Write a log message
    CWEBSOCKET_LOG_INFO("Test message to all backends");
    cwebsocket_log_flush();

    // Verify all backends received the message
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_SYSLOG),
           "Syslog backend enabled");
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_STDERR),
           "Stderr backend enabled");
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_FILE),
           "File backend enabled");
    ASSERT(cwebsocket_log_is_backend_enabled(CWEBSOCKET_LOG_BACKEND_CALLBACK),
           "Callback backend enabled");
    ASSERT(callback_invoked == 1, "Callback should receive message");

    struct stat st;
    ASSERT(stat(test_file, &st) == 0, "File should exist");
    ASSERT(st.st_size > 0, "File should have content");

    cwebsocket_log_set_file(NULL);
    unlink(test_file);

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void* thread_test_worker(void* arg) {
    int thread_id = *(int*)arg;

    for (int i = 0; i < 100; i++) {
        CWEBSOCKET_LOG_INFO("Thread %d message %d", thread_id, i);
    }

    return NULL;
}

void test_thread_safety(void) {
    TEST_START("Thread Safety");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_INFO);
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_SYSLOG, 0);

    const char *test_file = "/tmp/cwebsocket_thread_test.log";
    unlink(test_file);
    cwebsocket_log_set_file(test_file);

    // Enable thread safety
    int result = cwebsocket_log_set_thread_safe(1);
    ASSERT(result == 0, "Thread safety should be enabled successfully");

    // Create multiple threads
    const int num_threads = 4;
    pthread_t threads[num_threads];
    int thread_ids[num_threads];

    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, thread_test_worker, &thread_ids[i]);
    }

    // Wait for all threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    cwebsocket_log_flush();

    // Verify file has all messages
    struct stat st;
    ASSERT(stat(test_file, &st) == 0, "Log file should exist");
    ASSERT(st.st_size > 0, "Log file should have content");

    // Disable thread safety
    result = cwebsocket_log_set_thread_safe(0);
    ASSERT(result == 0, "Thread safety should be disabled successfully");

    cwebsocket_log_set_file(NULL);
    unlink(test_file);

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_macro_usage(void) {
    TEST_START("Logging Macro Usage");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_TRACE);

    callback_invoked = 0;
    cwebsocket_log_set_callback(test_callback, NULL);
    cwebsocket_log_set_backend(CWEBSOCKET_LOG_BACKEND_SYSLOG, 0);

    // Test all macro levels
    CWEBSOCKET_LOG_ERROR("Error: %d", 1);
    ASSERT(callback_invoked == 1 && callback_last_level == CWEBSOCKET_LOG_LEVEL_ERROR,
           "ERROR macro works");

    CWEBSOCKET_LOG_WARN("Warning: %d", 2);
    ASSERT(callback_invoked == 2 && callback_last_level == CWEBSOCKET_LOG_LEVEL_WARN,
           "WARN macro works");

    CWEBSOCKET_LOG_INFO("Info: %d", 3);
    ASSERT(callback_invoked == 3 && callback_last_level == CWEBSOCKET_LOG_LEVEL_INFO,
           "INFO macro works");

    CWEBSOCKET_LOG_DEBUG("Debug: %d", 4);
    ASSERT(callback_invoked == 4 && callback_last_level == CWEBSOCKET_LOG_LEVEL_DEBUG,
           "DEBUG macro works");

    CWEBSOCKET_LOG_TRACE("Trace: %d", 5);
    ASSERT(callback_invoked == 5 && callback_last_level == CWEBSOCKET_LOG_LEVEL_TRACE,
           "TRACE macro works");

    // Test MQTT-specific aliases
    MQTT_LOG_ERROR("MQTT Error");
    ASSERT(callback_invoked == 6 && callback_last_level == CWEBSOCKET_LOG_LEVEL_ERROR,
           "MQTT_LOG_ERROR alias works");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

void test_performance(void) {
    TEST_START("Performance (Disabled Logging)");

    cwebsocket_log_init();
    cwebsocket_log_set_level(CWEBSOCKET_LOG_LEVEL_NONE);  // Disable all logging

    // Time 100,000 log calls when logging is disabled
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < 100000; i++) {
        CWEBSOCKET_LOG_DEBUG("Debug message %d", i);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
                           (end.tv_nsec - start.tv_nsec);
    double elapsed_ms = elapsed_ns / 1000000.0;

    printf("  100,000 disabled log calls: %.2f ms\n", elapsed_ms);

    // Should be very fast when disabled (< 10ms)
    ASSERT(elapsed_ms < 100.0, "Disabled logging should have minimal overhead");

    cwebsocket_log_shutdown();
    TEST_PASS();
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main(void) {
    printf("=================================================\n");
    printf("  Configurable Logging System - Test Suite\n");
    printf("=================================================\n");

    test_initialization();
    test_log_levels();
    test_level_string_conversion();
    test_backend_configuration();
    test_file_backend();
    test_log_rotation();
    test_custom_callback();
    test_format_options();
    test_log_level_filtering();
    test_multiple_backends_simultaneously();
    test_thread_safety();
    test_macro_usage();
    test_performance();

    printf("\n=================================================\n");
    printf("  Test Results\n");
    printf("=================================================\n");
    printf("  Total:  %d\n", tests_run);
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("=================================================\n");

    if (tests_failed == 0) {
        printf("\n✓ All tests passed!\n\n");
        return 0;
    } else {
        printf("\n✗ %d test(s) failed!\n\n", tests_failed);
        return 1;
    }
}
