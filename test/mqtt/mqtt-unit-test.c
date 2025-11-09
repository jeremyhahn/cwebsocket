/**
 *  MQTT 5.0 Unit Tests
 *
 *  Fast unit tests that don't require a broker:
 *  - Property helper functions (creation and accessors)
 *  - Error handling and edge cases
 *  - Memory management
 *  - Input validation
 *
 *  Run with: make test-mqtt-unit
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../../src/cwebsocket/subprotocol/mqtt/mqtt_client.h"

// Test tracking
static int tests_passed = 0;
static int tests_failed = 0;

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

    if (tests_failed == 0) {
        printf("✓ All property helper tests PASSED\n\n");
    } else {
        printf("✗ Some tests FAILED\n\n");
    }
}

// Test 1: mqtt_property_create_payload_format_indicator()
void test_payload_format_indicator_helper() {
    print_test_header("Test 1: Payload Format Indicator Helper");

    // Test creating with UTF-8 flag
    mqtt_property *prop1 = mqtt_property_create_payload_format_indicator(1);
    ASSERT(prop1 != NULL, "Create payload format indicator (UTF-8)", "returned NULL");
    ASSERT(prop1->id == MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, "Property ID correct", "wrong ID");
    ASSERT(prop1->value.byte == 1, "UTF-8 flag set", "value mismatch");
    mqtt_property_free(prop1);

    // Test creating with binary flag
    mqtt_property *prop2 = mqtt_property_create_payload_format_indicator(0);
    ASSERT(prop2 != NULL, "Create payload format indicator (binary)", "returned NULL");
    ASSERT(prop2->value.byte == 0, "Binary flag set", "value mismatch");
    mqtt_property_free(prop2);

    // Test non-boolean value gets normalized to 0 or 1
    mqtt_property *prop3 = mqtt_property_create_payload_format_indicator(5);
    ASSERT(prop3 != NULL, "Create with non-boolean value", "returned NULL");
    ASSERT(prop3->value.byte == 1, "Non-zero normalized to 1", "normalization failed");
    mqtt_property_free(prop3);
}

// Test 2: mqtt_property_create_message_expiry()
void test_message_expiry_helper() {
    print_test_header("Test 2: Message Expiry Helper");

    // Test with various expiry values
    mqtt_property *prop1 = mqtt_property_create_message_expiry(3600);
    ASSERT(prop1 != NULL, "Create message expiry (3600s)", "returned NULL");
    ASSERT(prop1->id == MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, "Property ID correct", "wrong ID");
    ASSERT(prop1->value.u32 == 3600, "Expiry value correct", "value mismatch");
    mqtt_property_free(prop1);

    // Test with zero (immediate expiry)
    mqtt_property *prop2 = mqtt_property_create_message_expiry(0);
    ASSERT(prop2 != NULL, "Create message expiry (0s)", "returned NULL");
    ASSERT(prop2->value.u32 == 0, "Zero expiry correct", "value mismatch");
    mqtt_property_free(prop2);

    // Test with maximum value
    mqtt_property *prop3 = mqtt_property_create_message_expiry(0xFFFFFFFF);
    ASSERT(prop3 != NULL, "Create message expiry (max)", "returned NULL");
    ASSERT(prop3->value.u32 == 0xFFFFFFFF, "Max value correct", "value mismatch");
    mqtt_property_free(prop3);
}

// Test 3: mqtt_property_create_content_type()
void test_content_type_helper() {
    print_test_header("Test 3: Content Type Helper");

    // Test with valid content type
    mqtt_property *prop1 = mqtt_property_create_content_type("application/json");
    ASSERT(prop1 != NULL, "Create content type", "returned NULL");
    ASSERT(prop1->id == MQTT_PROP_CONTENT_TYPE, "Property ID correct", "wrong ID");
    ASSERT(prop1->value.string != NULL, "String allocated", "string is NULL");
    ASSERT(strcmp(prop1->value.string, "application/json") == 0, "Content type value", "value mismatch");
    mqtt_property_free(prop1);

    // Test with empty string
    mqtt_property *prop2 = mqtt_property_create_content_type("");
    ASSERT(prop2 != NULL, "Create content type (empty)", "returned NULL");
    ASSERT(strcmp(prop2->value.string, "") == 0, "Empty string correct", "value mismatch");
    mqtt_property_free(prop2);

    // Test with NULL input
    mqtt_property *prop3 = mqtt_property_create_content_type(NULL);
    ASSERT(prop3 == NULL, "NULL input returns NULL", "should return NULL");
}

// Test 4: mqtt_property_create_response_topic()
void test_response_topic_helper() {
    print_test_header("Test 4: Response Topic Helper");

    // Test with valid response topic
    mqtt_property *prop1 = mqtt_property_create_response_topic("response/topic");
    ASSERT(prop1 != NULL, "Create response topic", "returned NULL");
    ASSERT(prop1->id == MQTT_PROP_RESPONSE_TOPIC, "Property ID correct", "wrong ID");
    ASSERT(prop1->value.string != NULL, "String allocated", "string is NULL");
    ASSERT(strcmp(prop1->value.string, "response/topic") == 0, "Response topic value", "value mismatch");
    mqtt_property_free(prop1);

    // Test with topic containing wildcards (allowed in response topic)
    mqtt_property *prop2 = mqtt_property_create_response_topic("devices/+/status");
    ASSERT(prop2 != NULL, "Create response topic (with +)", "returned NULL");
    ASSERT(strcmp(prop2->value.string, "devices/+/status") == 0, "Wildcard topic correct", "value mismatch");
    mqtt_property_free(prop2);

    // Test with NULL input
    mqtt_property *prop3 = mqtt_property_create_response_topic(NULL);
    ASSERT(prop3 == NULL, "NULL input returns NULL", "should return NULL");
}

// Test 5: mqtt_property_create_correlation_data()
void test_correlation_data_helper() {
    print_test_header("Test 5: Correlation Data Helper");

    // Test with valid binary data
    uint8_t data1[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    mqtt_property *prop1 = mqtt_property_create_correlation_data(data1, 5);
    ASSERT(prop1 != NULL, "Create correlation data", "returned NULL");
    ASSERT(prop1->id == MQTT_PROP_CORRELATION_DATA, "Property ID correct", "wrong ID");
    ASSERT(prop1->value.binary.data != NULL, "Binary data allocated", "data is NULL");
    ASSERT(prop1->value.binary.len == 5, "Binary length correct", "length mismatch");
    ASSERT(memcmp(prop1->value.binary.data, data1, 5) == 0, "Binary data correct", "data mismatch");
    mqtt_property_free(prop1);

    // Test with single byte
    uint8_t data2[] = {0xFF};
    mqtt_property *prop2 = mqtt_property_create_correlation_data(data2, 1);
    ASSERT(prop2 != NULL, "Create correlation data (1 byte)", "returned NULL");
    ASSERT(prop2->value.binary.len == 1, "Single byte length", "length mismatch");
    ASSERT(prop2->value.binary.data[0] == 0xFF, "Single byte value", "value mismatch");
    mqtt_property_free(prop2);

    // Test with empty data (length 0)
    mqtt_property *prop3 = mqtt_property_create_correlation_data(data1, 0);
    ASSERT(prop3 == NULL, "Empty data returns NULL", "should return NULL for zero length");

    // Test with NULL data pointer
    mqtt_property *prop4 = mqtt_property_create_correlation_data(NULL, 5);
    ASSERT(prop4 == NULL, "NULL data returns NULL", "should return NULL");
}

// Test 6: mqtt_property_create_user_property()
void test_user_property_helper() {
    print_test_header("Test 6: User Property Helper");

    // Test with valid key-value pair
    mqtt_property *prop1 = mqtt_property_create_user_property("client-version", "1.0.0");
    ASSERT(prop1 != NULL, "Create user property", "returned NULL");
    ASSERT(prop1->id == MQTT_PROP_USER_PROPERTY, "Property ID correct", "wrong ID");
    ASSERT(prop1->value.user_property.key != NULL, "Key allocated", "key is NULL");
    ASSERT(prop1->value.user_property.value != NULL, "Value allocated", "value is NULL");
    ASSERT(strcmp(prop1->value.user_property.key, "client-version") == 0, "Key correct", "key mismatch");
    ASSERT(strcmp(prop1->value.user_property.value, "1.0.0") == 0, "Value correct", "value mismatch");
    mqtt_property_free(prop1);

    // Test with empty strings
    mqtt_property *prop2 = mqtt_property_create_user_property("", "");
    ASSERT(prop2 != NULL, "Create user property (empty strings)", "returned NULL");
    ASSERT(strcmp(prop2->value.user_property.key, "") == 0, "Empty key", "key mismatch");
    ASSERT(strcmp(prop2->value.user_property.value, "") == 0, "Empty value", "value mismatch");
    mqtt_property_free(prop2);

    // Test with NULL key
    mqtt_property *prop3 = mqtt_property_create_user_property(NULL, "value");
    ASSERT(prop3 == NULL, "NULL key returns NULL", "should return NULL");

    // Test with NULL value
    mqtt_property *prop4 = mqtt_property_create_user_property("key", NULL);
    ASSERT(prop4 == NULL, "NULL value returns NULL", "should return NULL");

    // Test with both NULL
    mqtt_property *prop5 = mqtt_property_create_user_property(NULL, NULL);
    ASSERT(prop5 == NULL, "NULL key and value returns NULL", "should return NULL");
}

// Test 7: mqtt_property_find()
void test_property_find() {
    print_test_header("Test 7: Property Find Helper");

    // Create a property list
    mqtt_property *props = NULL;
    mqtt_property **tail = &props;

    mqtt_property *p1 = mqtt_property_create(MQTT_PROP_CONTENT_TYPE);
    p1->value.string = strdup("application/json");
    *tail = p1;
    tail = &p1->next;

    mqtt_property *p2 = mqtt_property_create(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
    p2->value.u32 = 3600;
    *tail = p2;
    tail = &p2->next;

    mqtt_property *p3 = mqtt_property_create(MQTT_PROP_RESPONSE_TOPIC);
    p3->value.string = strdup("response/topic");
    *tail = p3;

    // Test finding existing properties
    mqtt_property *found1 = mqtt_property_find(props, MQTT_PROP_CONTENT_TYPE);
    ASSERT(found1 != NULL, "Find content type", "not found");
    ASSERT(found1->id == MQTT_PROP_CONTENT_TYPE, "Found property ID correct", "wrong property");

    mqtt_property *found2 = mqtt_property_find(props, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
    ASSERT(found2 != NULL, "Find message expiry", "not found");
    ASSERT(found2->value.u32 == 3600, "Found property value correct", "value mismatch");

    mqtt_property *found3 = mqtt_property_find(props, MQTT_PROP_RESPONSE_TOPIC);
    ASSERT(found3 != NULL, "Find response topic", "not found");
    ASSERT(strcmp(found3->value.string, "response/topic") == 0, "Found property string correct", "value mismatch");

    // Test finding non-existent property
    mqtt_property *not_found = mqtt_property_find(props, MQTT_PROP_CORRELATION_DATA);
    ASSERT(not_found == NULL, "Non-existent property returns NULL", "should return NULL");

    // Test with NULL list
    mqtt_property *found_null = mqtt_property_find(NULL, MQTT_PROP_CONTENT_TYPE);
    ASSERT(found_null == NULL, "Find in NULL list returns NULL", "should return NULL");

    mqtt_properties_free(props);
}

// Test 8: mqtt_property_get_string()
void test_property_get_string() {
    print_test_header("Test 8: Property Get String Helper");

    // Create properties
    mqtt_property *props = NULL;
    mqtt_property **tail = &props;

    mqtt_property *p1 = mqtt_property_create_content_type("application/json");
    *tail = p1;
    tail = &p1->next;

    mqtt_property *p2 = mqtt_property_create_response_topic("response/topic");
    *tail = p2;
    tail = &p2->next;

    mqtt_property *p3 = mqtt_property_create(MQTT_PROP_REASON_STRING);
    p3->value.string = strdup("All good");
    *tail = p3;

    // Test getting string properties
    const char *content = mqtt_property_get_string(props, MQTT_PROP_CONTENT_TYPE);
    ASSERT(content != NULL, "Get content type string", "returned NULL");
    ASSERT(strcmp(content, "application/json") == 0, "Content type value correct", "value mismatch");

    const char *response = mqtt_property_get_string(props, MQTT_PROP_RESPONSE_TOPIC);
    ASSERT(response != NULL, "Get response topic string", "returned NULL");
    ASSERT(strcmp(response, "response/topic") == 0, "Response topic value correct", "value mismatch");

    const char *reason = mqtt_property_get_string(props, MQTT_PROP_REASON_STRING);
    ASSERT(reason != NULL, "Get reason string", "returned NULL");
    ASSERT(strcmp(reason, "All good") == 0, "Reason string value correct", "value mismatch");

    // Test getting non-existent string property
    const char *not_found = mqtt_property_get_string(props, MQTT_PROP_AUTHENTICATION_METHOD);
    ASSERT(not_found == NULL, "Non-existent string property returns NULL", "should return NULL");

    // Test type mismatch (trying to get string from non-string property)
    mqtt_property *p4 = mqtt_property_create(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
    p4->value.u32 = 3600;
    p4->next = props;
    props = p4;

    const char *wrong_type = mqtt_property_get_string(props, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL);
    ASSERT(wrong_type == NULL, "Type mismatch returns NULL", "should return NULL for non-string type");

    // Test with NULL list
    const char *null_list = mqtt_property_get_string(NULL, MQTT_PROP_CONTENT_TYPE);
    ASSERT(null_list == NULL, "NULL list returns NULL", "should return NULL");

    mqtt_properties_free(props);
}

// Test 9: mqtt_property_get_u32()
void test_property_get_u32() {
    print_test_header("Test 9: Property Get U32 Helper");

    // Create properties
    mqtt_property *props = NULL;
    mqtt_property **tail = &props;

    mqtt_property *p1 = mqtt_property_create_message_expiry(3600);
    *tail = p1;
    tail = &p1->next;

    mqtt_property *p2 = mqtt_property_create(MQTT_PROP_SESSION_EXPIRY_INTERVAL);
    p2->value.u32 = 7200;
    *tail = p2;
    tail = &p2->next;

    mqtt_property *p3 = mqtt_property_create(MQTT_PROP_MAXIMUM_PACKET_SIZE);
    p3->value.u32 = 1048576;
    *tail = p3;

    // Test getting u32 properties
    uint32_t expiry = mqtt_property_get_u32(props, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 0);
    ASSERT(expiry == 3600, "Get message expiry u32", "value mismatch");

    uint32_t session = mqtt_property_get_u32(props, MQTT_PROP_SESSION_EXPIRY_INTERVAL, 0);
    ASSERT(session == 7200, "Get session expiry u32", "value mismatch");

    uint32_t packet_size = mqtt_property_get_u32(props, MQTT_PROP_MAXIMUM_PACKET_SIZE, 0);
    ASSERT(packet_size == 1048576, "Get maximum packet size u32", "value mismatch");

    // Test getting non-existent property (should return default)
    uint32_t not_found = mqtt_property_get_u32(props, MQTT_PROP_WILL_DELAY_INTERVAL, 9999);
    ASSERT(not_found == 9999, "Non-existent u32 returns default", "should return default value");

    // Test type mismatch
    mqtt_property *p4 = mqtt_property_create_content_type("text/plain");
    p4->next = props;
    props = p4;

    uint32_t wrong_type = mqtt_property_get_u32(props, MQTT_PROP_CONTENT_TYPE, 8888);
    ASSERT(wrong_type == 8888, "Type mismatch returns default", "should return default for wrong type");

    // Test with NULL list
    uint32_t null_list = mqtt_property_get_u32(NULL, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 7777);
    ASSERT(null_list == 7777, "NULL list returns default", "should return default");

    mqtt_properties_free(props);
}

// Test 10: mqtt_property_get_byte()
void test_property_get_byte() {
    print_test_header("Test 10: Property Get Byte Helper");

    // Create properties
    mqtt_property *props = NULL;
    mqtt_property **tail = &props;

    mqtt_property *p1 = mqtt_property_create_payload_format_indicator(1);
    *tail = p1;
    tail = &p1->next;

    mqtt_property *p2 = mqtt_property_create(MQTT_PROP_MAXIMUM_QOS);
    p2->value.byte = 2;
    *tail = p2;
    tail = &p2->next;

    mqtt_property *p3 = mqtt_property_create(MQTT_PROP_RETAIN_AVAILABLE);
    p3->value.byte = 1;
    *tail = p3;

    // Test getting byte properties
    uint8_t format = mqtt_property_get_byte(props, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 0);
    ASSERT(format == 1, "Get payload format byte", "value mismatch");

    uint8_t qos = mqtt_property_get_byte(props, MQTT_PROP_MAXIMUM_QOS, 0);
    ASSERT(qos == 2, "Get maximum QoS byte", "value mismatch");

    uint8_t retain = mqtt_property_get_byte(props, MQTT_PROP_RETAIN_AVAILABLE, 0);
    ASSERT(retain == 1, "Get retain available byte", "value mismatch");

    // Test getting non-existent property (should return default)
    uint8_t not_found = mqtt_property_get_byte(props, MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE, 99);
    ASSERT(not_found == 99, "Non-existent byte returns default", "should return default value");

    // Test type mismatch
    mqtt_property *p4 = mqtt_property_create_message_expiry(3600);
    p4->next = props;
    props = p4;

    uint8_t wrong_type = mqtt_property_get_byte(props, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 88);
    ASSERT(wrong_type == 88, "Type mismatch returns default", "should return default for wrong type");

    // Test with NULL list
    uint8_t null_list = mqtt_property_get_byte(NULL, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 77);
    ASSERT(null_list == 77, "NULL list returns default", "should return default");

    mqtt_properties_free(props);
}

// Test 11: Memory leak verification
void test_memory_management() {
    print_test_header("Test 11: Memory Management and Cleanup");

    // Create multiple properties and ensure proper cleanup
    mqtt_property *prop1 = mqtt_property_create_content_type("application/json");
    mqtt_property *prop2 = mqtt_property_create_response_topic("response/topic");
    mqtt_property *prop3 = mqtt_property_create_user_property("key", "value");

    uint8_t data[] = {0x01, 0x02, 0x03};
    mqtt_property *prop4 = mqtt_property_create_correlation_data(data, 3);

    // Chain them together
    prop1->next = prop2;
    prop2->next = prop3;
    prop3->next = prop4;

    // Free the entire chain
    mqtt_properties_free(prop1);
    TEST_PASS("Free property chain");

    // Create and free individual properties
    mqtt_property *p1 = mqtt_property_create_payload_format_indicator(1);
    mqtt_property_free(p1);
    TEST_PASS("Free payload format indicator");

    mqtt_property *p2 = mqtt_property_create_message_expiry(3600);
    mqtt_property_free(p2);
    TEST_PASS("Free message expiry");

    mqtt_property *p3 = mqtt_property_create_content_type("text/plain");
    mqtt_property_free(p3);
    TEST_PASS("Free content type");

    // Test freeing NULL (should not crash)
    mqtt_property_free(NULL);
    TEST_PASS("Free NULL property");
}

// Test 12: Complete workflow test
void test_complete_workflow() {
    print_test_header("Test 12: Complete Workflow Test");

    // Create a complete set of PUBLISH properties using helpers
    mqtt_property *props = NULL;
    mqtt_property **tail = &props;

    // Add payload format indicator
    mqtt_property *p1 = mqtt_property_create_payload_format_indicator(1);
    *tail = p1;
    tail = &p1->next;

    // Add message expiry
    mqtt_property *p2 = mqtt_property_create_message_expiry(7200);
    *tail = p2;
    tail = &p2->next;

    // Add content type
    mqtt_property *p3 = mqtt_property_create_content_type("application/json");
    *tail = p3;
    tail = &p3->next;

    // Add response topic
    mqtt_property *p4 = mqtt_property_create_response_topic("response/data");
    *tail = p4;
    tail = &p4->next;

    // Add correlation data
    uint8_t corr[] = {0xAA, 0xBB, 0xCC};
    mqtt_property *p5 = mqtt_property_create_correlation_data(corr, 3);
    *tail = p5;
    tail = &p5->next;

    // Add user properties
    mqtt_property *p6 = mqtt_property_create_user_property("client", "cwebsocket");
    *tail = p6;
    tail = &p6->next;

    mqtt_property *p7 = mqtt_property_create_user_property("version", "2.0.0");
    *tail = p7;

    // Verify all properties can be accessed
    uint8_t format = mqtt_property_get_byte(props, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 0);
    ASSERT(format == 1, "Workflow: payload format", "value mismatch");

    uint32_t expiry = mqtt_property_get_u32(props, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 0);
    ASSERT(expiry == 7200, "Workflow: message expiry", "value mismatch");

    const char *content = mqtt_property_get_string(props, MQTT_PROP_CONTENT_TYPE);
    ASSERT(strcmp(content, "application/json") == 0, "Workflow: content type", "value mismatch");

    const char *response = mqtt_property_get_string(props, MQTT_PROP_RESPONSE_TOPIC);
    ASSERT(strcmp(response, "response/data") == 0, "Workflow: response topic", "value mismatch");

    mqtt_property *corr_prop = mqtt_property_find(props, MQTT_PROP_CORRELATION_DATA);
    ASSERT(corr_prop != NULL, "Workflow: find correlation data", "not found");
    ASSERT(memcmp(corr_prop->value.binary.data, corr, 3) == 0, "Workflow: correlation data value", "value mismatch");

    // Verify user properties
    int user_prop_count = 0;
    mqtt_property *current = props;
    while (current) {
        if (current->id == MQTT_PROP_USER_PROPERTY) {
            user_prop_count++;
        }
        current = current->next;
    }
    ASSERT(user_prop_count == 2, "Workflow: user property count", "count mismatch");

    // Clean up
    mqtt_properties_free(props);
    TEST_PASS("Workflow: cleanup");
}

int main() {
    printf("\n");
    printf("========================================\n");
    printf("  MQTT 5.0 Property Helper Functions Test\n");
    printf("  Testing all creation and accessor helpers\n");
    printf("========================================\n");
    printf("\n");

    // Run all tests
    test_payload_format_indicator_helper();
    test_message_expiry_helper();
    test_content_type_helper();
    test_response_topic_helper();
    test_correlation_data_helper();
    test_user_property_helper();
    test_property_find();
    test_property_get_string();
    test_property_get_u32();
    test_property_get_byte();
    test_memory_management();
    test_complete_workflow();

    print_test_results();

    return (tests_failed == 0) ? 0 : 1;
}
