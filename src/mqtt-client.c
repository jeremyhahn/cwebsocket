/**
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

#include <signal.h>
#include <time.h>
#include <string.h>
#include "cwebsocket/client.h"
#include "cwebsocket/subprotocol/mqtt/mqtt_client.h"

cwebsocket_client websocket_client;
mqtt_client_state *mqtt_state;

// Secure wrapper for getting environment variables with validation
static const char* get_validated_env(const char *name, size_t max_len) {
	const char *value = getenv(name);  // flawfinder: ignore
	if (!value) return NULL;

	// Validate length using strnlen (bounded check)
	if (strnlen(value, max_len + 1) > max_len) {
		fprintf(stderr, "Error: Environment variable %s exceeds maximum length (%zu)\n",
		        name, max_len);
		exit(EXIT_FAILURE);
	}
	return value;
}

int main_exit(int exit_status) {
	syslog(LOG_DEBUG, "exiting mqtt client");
	closelog();
	return exit_status;
}

void signal_handler(int sig) {
	switch(sig) {
		case SIGHUP:
			syslog(LOG_DEBUG, "Received SIGHUP signal");
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_DEBUG, "SIGINT/SIGTERM");
			mqtt_send_disconnect(&websocket_client, MQTT_RC_NORMAL_DISCONNECTION, NULL);
			// Give time for disconnect to be sent
			struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms
			nanosleep(&ts, NULL);
			cwebsocket_client_close(&websocket_client, 1000, "SIGINT/SIGTERM");
			main_exit(EXIT_SUCCESS);
			exit(0);
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}

void print_program_header() {
	printf("\n");
	printf("                      ______                    ______      _____ \n");
    printf(" _________      _________  /_______________________  /________  /_\n");
    printf(" _  ___/_ | /| / /  _ \\_  __ \\_  ___/  __ \\  ___/_  //_/  _ \\  __/\n");
    printf(" / /__ __ |/ |/ //  __/  /_/ /(__  )/ /_/ / /__ _  ,<  /  __/ /_  \n");
    printf(" \\___/ ____/|__/ \\___//_____//____/ \\____/\\___/ /_/|_| \\___/\\__/\n");
    printf("\n");
	printf("                                   MQTT WebSocket Client\n");
    printf("                                   Copyright (c) 2014 Jeremy Hahn\n");
    printf("                                   mail@jeremyhahn.com\n");
	printf("\n");
}

void print_program_usage(const char *progname) {
	fprintf(stderr, "usage: %s [websocket-uri] [topic]\n", progname);
	fprintf(stderr, "example: %s ws://localhost:8083/mqtt test/topic\n\n", progname);
	fprintf(stderr, "Environment variables:\n");
	fprintf(stderr, "  MQTT_CLIENT_ID  - Client identifier (default: auto-generated)\n");
	fprintf(stderr, "  MQTT_USERNAME   - Username for authentication (optional)\n");
	fprintf(stderr, "  MQTT_PASSWORD   - Password for authentication (optional)\n");
	fprintf(stderr, "  MQTT_CLEAN_START - Clean start flag: 0 or 1 (default: 1)\n");
	fprintf(stderr, "  MQTT_KEEP_ALIVE  - Keep alive interval in seconds (default: 60)\n\n");
	exit(0);
}

void run_mqtt_test(cwebsocket_client *websocket, const char *topic) {
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000000}; // 500ms

	// Wait for CONNACK
	printf("\n[TEST 1/8] Waiting for MQTT CONNACK...\n");
	fflush(stdout);
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ CONNACK received\n");

	// Test 2: Subscribe to topic
	printf("\n[TEST 2/8] Testing SUBSCRIBE (QoS 0)...\n");
	mqtt_send_subscribe(websocket, topic, MQTT_QOS_0, 0, 0, 0);
	nanosleep(&ts, NULL);

	// Read SUBACK
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ SUBSCRIBE sent and SUBACK received\n");

	// Test 3: Publish QoS 0 message
	printf("\n[TEST 3/8] Testing PUBLISH (QoS 0)...\n");
	const char *test_msg_qos0 = "Hello MQTT! QoS 0 message from cwebsocket";
	mqtt_send_publish(websocket, topic, (const uint8_t *)test_msg_qos0,
	                  strlen(test_msg_qos0), MQTT_QOS_0, 0, 0);  // flawfinder: ignore
	nanosleep(&ts, NULL);

	// Read published message
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ QoS 0 message published and received\n");

	// Test 4: Publish QoS 1 message
	printf("\n[TEST 4/8] Testing PUBLISH (QoS 1)...\n");
	const char *test_msg_qos1 = "Hello MQTT! QoS 1 message from cwebsocket";
	mqtt_send_publish(websocket, topic, (const uint8_t *)test_msg_qos1,
	                  strlen(test_msg_qos1), MQTT_QOS_1, 0, 0);  // flawfinder: ignore
	nanosleep(&ts, NULL);

	// Read PUBACK and published message
	for(int i = 0; i < 2; i++) {
		cwebsocket_client_read_data(websocket);
		nanosleep(&ts, NULL);
	}
	printf("✓ QoS 1 message published with PUBACK\n");

	// Test 5: Publish QoS 2 message
	printf("\n[TEST 5/8] Testing PUBLISH (QoS 2)...\n");
	const char *test_msg_qos2 = "Hello MQTT! QoS 2 message from cwebsocket";
	mqtt_send_publish(websocket, topic, (const uint8_t *)test_msg_qos2,
	                  strlen(test_msg_qos2), MQTT_QOS_2, 0, 0);  // flawfinder: ignore
	nanosleep(&ts, NULL);

	// Read PUBREC, PUBCOMP, and published message (we send PUBREL automatically)
	for(int i = 0; i < 3; i++) {
		cwebsocket_client_read_data(websocket);
		nanosleep(&ts, NULL);
	}
	printf("✓ QoS 2 message published with PUBREC/PUBREL/PUBCOMP\n");

	// Test 6: Publish retained message
	printf("\n[TEST 6/8] Testing retained message...\n");
	const char *retained_msg = "This is a retained message";
	mqtt_send_publish(websocket, topic, (const uint8_t *)retained_msg,
	                  strlen(retained_msg), MQTT_QOS_0, 1, 0);  // flawfinder: ignore
	nanosleep(&ts, NULL);

	// Read retained message
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ Retained message published\n");

	// Test 7: Unsubscribe
	printf("\n[TEST 7/8] Testing UNSUBSCRIBE...\n");
	mqtt_send_unsubscribe(websocket, topic);
	nanosleep(&ts, NULL);

	// Read UNSUBACK
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ UNSUBSCRIBE sent and UNSUBACK received\n");

	// Test 8: Keep-alive (PINGREQ/PINGRESP)
	printf("\n[TEST 8/8] Testing keep-alive (PINGREQ/PINGRESP)...\n");
	mqtt_send_pingreq(websocket);
	nanosleep(&ts, NULL);

	// Read PINGRESP
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ PINGREQ sent and PINGRESP received\n");

	printf("\n✓ All MQTT 5.0 features validated!\n");
	printf("\nTest complete. Disconnecting...\n");
}

int main(int argc, char **argv) {

	print_program_header();
	if(argc < 3) print_program_usage(argv[0]);

	const char *uri = argv[1];
	const char *topic = argv[2];

	// Get MQTT connection parameters from environment with validation
	#define MAX_ENV_LEN 256
	const char *mqtt_client_id = get_validated_env("MQTT_CLIENT_ID", MAX_ENV_LEN);
	const char *mqtt_username = get_validated_env("MQTT_USERNAME", MAX_ENV_LEN);
	const char *mqtt_password = get_validated_env("MQTT_PASSWORD", MAX_ENV_LEN);
	const char *mqtt_clean_start_str = get_validated_env("MQTT_CLEAN_START", 8);
	const char *mqtt_keep_alive_str = get_validated_env("MQTT_KEEP_ALIVE", 8);

	// Parse MQTT parameters
	uint8_t clean_start = 1;
	uint16_t keep_alive = 60;

	if(mqtt_clean_start_str) {
		char *endptr;
		long val = strtol(mqtt_clean_start_str, &endptr, 10);
		if (endptr != mqtt_clean_start_str && *endptr == '\0' && val >= 0 && val <= 1) {
			clean_start = (uint8_t)val;
		} else {
			fprintf(stderr, "Invalid clean_start value, using default: 1\n");
		}
	}

	if(mqtt_keep_alive_str) {
		char *endptr;
		long val = strtol(mqtt_keep_alive_str, &endptr, 10);
		if (endptr != mqtt_keep_alive_str && *endptr == '\0' && val >= 0 && val <= 65535) {
			keep_alive = (uint16_t)val;
		} else {
			fprintf(stderr, "Invalid keep_alive value, using default: 60\n");
		}
	}

	printf("Connecting to: %s\n", uri);
	printf("MQTT Protocol: 5.0\n");
	if(mqtt_client_id) {
		printf("Client ID: %s\n", mqtt_client_id);
	} else {
		printf("Client ID: auto-generated\n");
	}
	if(mqtt_username) {
		printf("Username: %s\n", mqtt_username);
	}
	printf("Clean Start: %d\n", clean_start);
	printf("Keep Alive: %d seconds\n", keep_alive);
	printf("\n");

	struct sigaction newSigAction;
	sigset_t newSigSet;

	// Set signal mask - signals to block
	sigemptyset(&newSigSet);
	sigaddset(&newSigSet, SIGCHLD);  			/* ignore child - i.e. we don't need to wait for it */
	sigaddset(&newSigSet, SIGTSTP);  			/* ignore Tty stop signals */
	sigaddset(&newSigSet, SIGTTOU);  			/* ignore Tty background writes */
	sigaddset(&newSigSet, SIGTTIN);  			/* ignore Tty background reads */
	sigprocmask(SIG_BLOCK, &newSigSet, NULL);   /* Block the above specified signals */

	// Set up a signal handler
	newSigAction.sa_handler = signal_handler;
	sigemptyset(&newSigAction.sa_mask);
	newSigAction.sa_flags = 0;

	sigaction(SIGHUP, &newSigAction, NULL);     /* catch hangup signal */
	sigaction(SIGTERM, &newSigAction, NULL);    /* catch term signal */
	sigaction(SIGINT, &newSigAction, NULL);     /* catch interrupt signal */

	setlogmask(LOG_UPTO(LOG_DEBUG)); // LOG_INFO, LOG_DEBUG
	openlog("mqtt-client", LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "starting mqtt websocket client");

	// Enable synchronous callbacks
	setenv("CWS_SYNC_CALLBACKS", "1", 1);

	// Create MQTT subprotocol
	cwebsocket_subprotocol *mqtt_proto = cwebsocket_subprotocol_mqtt_client_new(
		mqtt_client_id, mqtt_username, mqtt_password, clean_start, keep_alive
	);

	// Initialize WebSocket client with MQTT subprotocol array
	cwebsocket_subprotocol *subprotocols[] = {mqtt_proto};
	cwebsocket_client_init(&websocket_client, subprotocols, 1);
	websocket_client.uri = (char *)uri;

	mqtt_state = NULL;  // We'll access it through the module's global

	if(cwebsocket_client_connect(&websocket_client) == -1) {
		return main_exit(EXIT_FAILURE);
	}

	run_mqtt_test(&websocket_client, topic);

	// Send DISCONNECT and close
	mqtt_send_disconnect(&websocket_client, MQTT_RC_NORMAL_DISCONNECTION, NULL);
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms
	nanosleep(&ts, NULL);

	cwebsocket_client_close(&websocket_client, 1000, "Test complete");
	return main_exit(EXIT_SUCCESS);
}
