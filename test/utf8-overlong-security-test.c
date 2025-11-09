/**
 * CRITICAL SECURITY TEST: UTF-8 Overlong Encoding Detection
 *
 * This test verifies that the UTF-8 validator rejects ALL overlong encodings,
 * which are a common attack vector for bypassing security checks.
 *
 * Background:
 * Overlong encodings represent valid Unicode codepoints using more bytes
 * than necessary. While technically representing the same character, they
 * can bypass validation logic that doesn't normalize input.
 *
 * Example attack vector:
 * - Normal forward slash: 0x2F (/)
 * - Overlong forward slash: 0xC0 0xAF
 * - Could bypass path traversal protection, ACL checks, etc.
 *
 * RFC 3629 explicitly forbids overlong encodings.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../src/cwebsocket/utf8.h"

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

/**
 * Test 2-byte overlong encodings.
 * These use 0xC0 or 0xC1 as the first byte and encode ASCII characters
 * (U+0000 to U+007F) which should only use 1 byte.
 */
static void test_2byte_overlong_encodings() {
    TEST(test_2byte_overlong_encodings);

    size_t count;
    int rc;

    // Overlong NULL: 0xC0 0x80 (should be 0x00)
    uint8_t overlong_null[] = {0xC0, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_null, &count);
    if(rc == 0) {
        FAIL("Should reject overlong NULL (0xC0 0x80)");
        return;
    }

    // Overlong forward slash: 0xC0 0xAF (should be 0x2F)
    // This is the classic security attack example
    uint8_t overlong_slash[] = {0xC0, 0xAF, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_slash, &count);
    if(rc == 0) {
        FAIL("Should reject overlong / (0xC0 0xAF) - CRITICAL SECURITY ISSUE");
        return;
    }

    // Overlong backslash: 0xC1 0x9C (should be 0x5C)
    // Another path traversal attack vector
    uint8_t overlong_backslash[] = {0xC1, 0x9C, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_backslash, &count);
    if(rc == 0) {
        FAIL("Should reject overlong \\ (0xC1 0x9C) - CRITICAL SECURITY ISSUE");
        return;
    }

    // Overlong space: 0xC0 0xA0 (should be 0x20)
    uint8_t overlong_space[] = {0xC0, 0xA0, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_space, &count);
    if(rc == 0) {
        FAIL("Should reject overlong space (0xC0 0xA0)");
        return;
    }

    // Overlong dot: 0xC0 0xAE (should be 0x2E)
    // Path traversal: "../"
    uint8_t overlong_dot[] = {0xC0, 0xAE, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_dot, &count);
    if(rc == 0) {
        FAIL("Should reject overlong . (0xC0 0xAE) - path traversal attack");
        return;
    }

    // Test all possible 2-byte overlong encodings
    // 0xC0 and 0xC1 with any continuation byte encode U+0000 to U+007F
    for(uint8_t first = 0xC0; first <= 0xC1; first++) {
        for(uint8_t second = 0x80; second <= 0xBF; second++) {
            uint8_t test_seq[] = {first, second, 0x00};
            count = 0;
            rc = utf8_count_code_points(test_seq, &count);
            if(rc == 0) {
                char err_msg[100];
                snprintf(err_msg, sizeof(err_msg),
                        "Should reject 2-byte overlong 0x%02X 0x%02X", first, second);
                FAIL(err_msg);
                return;
            }
        }
    }

    PASS();
}

/**
 * Test 3-byte overlong encodings.
 * These start with 0xE0 0x80-0x9F and encode codepoints U+0000 to U+07FF
 * which should use 1 or 2 bytes.
 */
static void test_3byte_overlong_encodings() {
    TEST(test_3byte_overlong_encodings);

    size_t count;
    int rc;

    // Overlong NULL: 0xE0 0x80 0x80 (should be 0x00)
    uint8_t overlong_null[] = {0xE0, 0x80, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_null, &count);
    if(rc == 0) {
        FAIL("Should reject 3-byte overlong NULL (0xE0 0x80 0x80)");
        return;
    }

    // Overlong forward slash: 0xE0 0x80 0xAF (should be 0x2F)
    uint8_t overlong_slash[] = {0xE0, 0x80, 0xAF, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_slash, &count);
    if(rc == 0) {
        FAIL("Should reject 3-byte overlong / (0xE0 0x80 0xAF)");
        return;
    }

    // Overlong encoding of U+07FF (highest 2-byte character)
    // Valid: 0xDF 0xBF, Overlong: 0xE0 0x9F 0xBF
    uint8_t overlong_07ff[] = {0xE0, 0x9F, 0xBF, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_07ff, &count);
    if(rc == 0) {
        FAIL("Should reject 3-byte overlong U+07FF (0xE0 0x9F 0xBF)");
        return;
    }

    // Test range of 3-byte overlong encodings
    // 0xE0 0x80-0x9F encode codepoints that should use 1-2 bytes
    for(uint8_t second = 0x80; second <= 0x9F; second++) {
        uint8_t test_seq[] = {0xE0, second, 0x80, 0x00};
        count = 0;
        rc = utf8_count_code_points(test_seq, &count);
        if(rc == 0) {
            char err_msg[100];
            snprintf(err_msg, sizeof(err_msg),
                    "Should reject 3-byte overlong 0xE0 0x%02X 0x80", second);
            FAIL(err_msg);
            return;
        }
    }

    // Valid 3-byte sequence should still work
    // U+0800 = 0xE0 0xA0 0x80 (first valid 3-byte encoding)
    uint8_t valid_0800[] = {0xE0, 0xA0, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(valid_0800, &count);
    if(rc != 0 || count != 1) {
        FAIL("Valid 3-byte U+0800 should be accepted");
        return;
    }

    PASS();
}

/**
 * Test 4-byte overlong encodings.
 * These start with 0xF0 0x80-0x8F and encode codepoints U+0000 to U+FFFF
 * which should use 1, 2, or 3 bytes.
 */
static void test_4byte_overlong_encodings() {
    TEST(test_4byte_overlong_encodings);

    size_t count;
    int rc;

    // Overlong NULL: 0xF0 0x80 0x80 0x80 (should be 0x00)
    uint8_t overlong_null[] = {0xF0, 0x80, 0x80, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_null, &count);
    if(rc == 0) {
        FAIL("Should reject 4-byte overlong NULL (0xF0 0x80 0x80 0x80)");
        return;
    }

    // Overlong forward slash: 0xF0 0x80 0x80 0xAF (should be 0x2F)
    uint8_t overlong_slash[] = {0xF0, 0x80, 0x80, 0xAF, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_slash, &count);
    if(rc == 0) {
        FAIL("Should reject 4-byte overlong / (0xF0 0x80 0x80 0xAF)");
        return;
    }

    // Overlong encoding of U+FFFF (highest 3-byte character)
    // Valid: 0xEF 0xBF 0xBF, Overlong: 0xF0 0x8F 0xBF 0xBF
    uint8_t overlong_ffff[] = {0xF0, 0x8F, 0xBF, 0xBF, 0x00};
    count = 0;
    rc = utf8_count_code_points(overlong_ffff, &count);
    if(rc == 0) {
        FAIL("Should reject 4-byte overlong U+FFFF (0xF0 0x8F 0xBF 0xBF)");
        return;
    }

    // Test range of 4-byte overlong encodings
    // 0xF0 0x80-0x8F encode codepoints that should use 1-3 bytes
    for(uint8_t second = 0x80; second <= 0x8F; second++) {
        uint8_t test_seq[] = {0xF0, second, 0x80, 0x80, 0x00};
        count = 0;
        rc = utf8_count_code_points(test_seq, &count);
        if(rc == 0) {
            char err_msg[100];
            snprintf(err_msg, sizeof(err_msg),
                    "Should reject 4-byte overlong 0xF0 0x%02X 0x80 0x80", second);
            FAIL(err_msg);
            return;
        }
    }

    // Valid 4-byte sequence should still work
    // U+10000 = 0xF0 0x90 0x80 0x80 (first valid 4-byte encoding)
    uint8_t valid_10000[] = {0xF0, 0x90, 0x80, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(valid_10000, &count);
    if(rc != 0 || count != 1) {
        FAIL("Valid 4-byte U+10000 should be accepted");
        return;
    }

    PASS();
}

/**
 * Test mixed valid and overlong sequences.
 * Ensure that overlong detection doesn't break normal validation.
 */
static void test_mixed_sequences() {
    TEST(test_mixed_sequences);

    size_t count;
    int rc;

    // Valid ASCII followed by overlong
    uint8_t valid_then_overlong[] = {'H', 'e', 'l', 'l', 'o', 0xC0, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(valid_then_overlong, &count);
    if(rc == 0) {
        FAIL("Should reject string with overlong in middle");
        return;
    }

    // All valid sequences
    uint8_t all_valid[] = {
        'A',                    // 1-byte: ASCII
        0xC2, 0xA9,            // 2-byte: © (U+00A9)
        0xE2, 0x82, 0xAC,      // 3-byte: € (U+20AC)
        0xF0, 0x9F, 0x98, 0x80,// 4-byte: 😀 (U+1F600)
        0x00
    };
    count = 0;
    rc = utf8_count_code_points(all_valid, &count);
    if(rc != 0 || count != 4) {
        FAIL("Should accept all valid sequences");
        return;
    }

    // Valid 2-byte that looks similar to overlong
    // 0xC2 0x80 is valid (U+0080) vs 0xC0 0x80 overlong (U+0000)
    uint8_t valid_c2[] = {0xC2, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(valid_c2, &count);
    if(rc != 0 || count != 1) {
        FAIL("Should accept valid 2-byte U+0080 (0xC2 0x80)");
        return;
    }

    PASS();
}

/**
 * Test security-critical attack sequences.
 * These are real-world attack patterns that must be blocked.
 */
static void test_security_attack_sequences() {
    TEST(test_security_attack_sequences);

    size_t count;
    int rc;

    // Path traversal attack: overlong "/../"
    // Normal: 0x2F 0x2E 0x2E 0x2F
    // Overlong: 0xC0 0xAF 0xC0 0xAE 0xC0 0xAE 0xC0 0xAF
    uint8_t attack_path_traversal[] = {
        0xC0, 0xAF, 0xC0, 0xAE, 0xC0, 0xAE, 0xC0, 0xAF, 0x00
    };
    count = 0;
    rc = utf8_count_code_points(attack_path_traversal, &count);
    if(rc == 0) {
        FAIL("Should reject overlong path traversal attack /../");
        return;
    }

    // SQL injection bypass: overlong single quote
    // Normal: 0x27 (')
    // Overlong: 0xC0 0xA7
    uint8_t attack_sql_quote[] = {0xC0, 0xA7, 0x00};
    count = 0;
    rc = utf8_count_code_points(attack_sql_quote, &count);
    if(rc == 0) {
        FAIL("Should reject overlong single quote (SQL injection)");
        return;
    }

    // XSS attack: overlong "<script>"
    // Normal: 0x3C 0x73 0x63 0x72 0x69 0x70 0x74 0x3E
    // Overlong (just <): 0xC0 0xBC
    uint8_t attack_xss[] = {0xC0, 0xBC, 's', 'c', 'r', 'i', 'p', 't', '>', 0x00};
    count = 0;
    rc = utf8_count_code_points(attack_xss, &count);
    if(rc == 0) {
        FAIL("Should reject overlong < (XSS attack)");
        return;
    }

    // Command injection: overlong semicolon
    // Normal: 0x3B (;)
    // Overlong: 0xC0 0xBB
    uint8_t attack_semicolon[] = {0xC0, 0xBB, 0x00};
    count = 0;
    rc = utf8_count_code_points(attack_semicolon, &count);
    if(rc == 0) {
        FAIL("Should reject overlong ; (command injection)");
        return;
    }

    // Null byte injection: overlong NULL
    // Used to truncate strings in C
    // Normal: 0x00
    // Overlong: 0xC0 0x80 or 0xE0 0x80 0x80 or 0xF0 0x80 0x80 0x80
    uint8_t attack_null_2byte[] = {0xC0, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(attack_null_2byte, &count);
    if(rc == 0) {
        FAIL("Should reject 2-byte overlong NULL (string truncation)");
        return;
    }

    uint8_t attack_null_3byte[] = {0xE0, 0x80, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(attack_null_3byte, &count);
    if(rc == 0) {
        FAIL("Should reject 3-byte overlong NULL (string truncation)");
        return;
    }

    uint8_t attack_null_4byte[] = {0xF0, 0x80, 0x80, 0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(attack_null_4byte, &count);
    if(rc == 0) {
        FAIL("Should reject 4-byte overlong NULL (string truncation)");
        return;
    }

    PASS();
}

/**
 * Test that existing surrogate and invalid sequence detection still works.
 */
static void test_existing_validation() {
    TEST(test_existing_validation);

    size_t count;
    int rc;

    // Invalid continuation byte without lead byte
    uint8_t invalid_continuation[] = {0x80, 0x00};
    count = 0;
    rc = utf8_count_code_points(invalid_continuation, &count);
    if(rc == 0) {
        FAIL("Should reject invalid continuation byte");
        return;
    }

    // Truncated sequence
    uint8_t truncated[] = {0xC2, 0x00}; // 2-byte sequence with only 1 byte
    count = 0;
    rc = utf8_count_code_points(truncated, &count);
    if(rc == 0) {
        FAIL("Should reject truncated sequence");
        return;
    }

    // Valid sequences should still work
    uint8_t valid_ascii[] = "Hello, World!";
    count = 0;
    rc = utf8_count_code_points(valid_ascii, &count);
    if(rc != 0 || count != 13) {
        FAIL("Should accept valid ASCII");
        return;
    }

    PASS();
}

int main(void) {
    printf("=== CRITICAL SECURITY TEST: UTF-8 Overlong Encoding Detection ===\n\n");
    printf("This test verifies protection against overlong encoding attacks.\n");
    printf("Overlong encodings are a common attack vector for bypassing security checks.\n\n");

    // Run comprehensive overlong detection tests
    test_2byte_overlong_encodings();
    test_3byte_overlong_encodings();
    test_4byte_overlong_encodings();
    test_mixed_sequences();
    test_security_attack_sequences();
    test_existing_validation();

    // Summary
    printf("\n=== Test Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n", tests_passed + tests_failed);

    if(tests_failed == 0) {
        printf("\n✓ All security tests passed!\n");
        printf("✓ System is protected against overlong encoding attacks.\n");
        return 0;
    } else {
        printf("\n✗ CRITICAL: Some security tests failed!\n");
        printf("✗ System is VULNERABLE to overlong encoding attacks!\n");
        return 1;
    }
}
