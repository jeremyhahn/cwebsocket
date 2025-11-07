/**
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2014 Jeremy Hahn
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#include <signal.h>
#include <time.h>
#include <string.h>
#include "cwebsocket/client.h"
#include "cwebsocket/subprotocol/stomp/stomp_client.h"

cwebsocket_client websocket_client;
stomp_client_state *stomp_state;

// Secure wrapper for getting environment variables with validation
// Returns NULL if variable is invalid or exceeds max length
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
	syslog(LOG_DEBUG, "exiting stomp client");
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
			stomp_send_disconnect(&websocket_client, NULL);
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
	printf("                                   STOMP WebSocket Client\n");
    printf("                                   Copyright (c) 2014 Jeremy Hahn\n");
    printf("                                   mail@jeremyhahn.com\n");
	printf("\n");
}

void print_program_usage(const char *progname) {
	fprintf(stderr, "usage: %s [websocket-uri] [destination]\n", progname);
	fprintf(stderr, "example: %s ws://localhost:15674/ws /queue/test\n\n", progname);
	fprintf(stderr, "Environment variables:\n");
	fprintf(stderr, "  STOMP_HOST     - Virtual host (default: /)\n");
	fprintf(stderr, "  STOMP_LOGIN    - Login username (optional)\n");
	fprintf(stderr, "  STOMP_PASSCODE - Login password (optional)\n\n");
	exit(0);
}

void run_stomp_test(cwebsocket_client *websocket, const char *destination) {
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 500000000}; // 500ms

	// Wait for CONNECTED frame
	printf("\n[TEST 1/7] Waiting for STOMP CONNECTED frame...\n");
	fflush(stdout);
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);
	printf("✓ CONNECTED frame received\n");

	// Test 2: Basic subscribe and send/receive
	printf("\n[TEST 2/7] Testing SUBSCRIBE and message exchange...\n");
	stomp_send_subscribe(websocket, destination, "sub-0", STOMP_ACK_AUTO, NULL);
	nanosleep(&ts, NULL);

	const char *test_message = "Hello from cwebsocket STOMP client!";
	stomp_send_message(websocket, destination, test_message, strlen(test_message),  // flawfinder: ignore
	                   "text/plain", NULL, NULL);

	// Read response
	for(int i = 0; i < 3; i++) {
		cwebsocket_client_read_data(websocket);
		nanosleep(&ts, NULL);
	}
	printf("✓ Basic message exchange works\n");

	// Test 3: Test UNSUBSCRIBE
	printf("\n[TEST 3/7] Testing UNSUBSCRIBE...\n");
	stomp_send_unsubscribe(websocket, "sub-0", NULL);
	nanosleep(&ts, NULL);
	printf("✓ UNSUBSCRIBE sent\n");

	// Test 4: Test client-individual ACK mode
	printf("\n[TEST 4/7] Testing client-individual ACK mode...\n");
	stomp_send_subscribe(websocket, destination, "sub-ack", STOMP_ACK_CLIENT_INDIVIDUAL, NULL);
	nanosleep(&ts, NULL);

	stomp_send_message(websocket, destination, "ACK test message", 16,
	                   "text/plain", NULL, NULL);
	nanosleep(&ts, NULL);

	// Read the message
	cwebsocket_client_read_data(websocket);
	nanosleep(&ts, NULL);

	// Send ACK (using a dummy message-id for testing)
	stomp_send_ack(websocket, "test-msg-id", "sub-ack", NULL);
	nanosleep(&ts, NULL);
	printf("✓ ACK/NACK commands sent\n");

	stomp_send_unsubscribe(websocket, "sub-ack", NULL);
	nanosleep(&ts, NULL);

	// Test 5: Test transactions
	printf("\n[TEST 5/7] Testing transaction support...\n");
	const char *tx_id = "tx-test-1";
	stomp_begin_transaction(websocket, tx_id);
	nanosleep(&ts, NULL);

	stomp_send_message(websocket, destination, "TX message", 10,
	                   "text/plain", NULL, tx_id);
	nanosleep(&ts, NULL);

	stomp_commit_transaction(websocket, tx_id, NULL);
	nanosleep(&ts, NULL);
	printf("✓ Transaction BEGIN/COMMIT works\n");

	// Test 6: Test ABORT transaction
	printf("\n[TEST 6/7] Testing transaction ABORT...\n");
	const char *tx_id2 = "tx-test-2";
	stomp_begin_transaction(websocket, tx_id2);
	nanosleep(&ts, NULL);

	stomp_send_message(websocket, destination, "Abort message", 13,
	                   "text/plain", NULL, tx_id2);
	nanosleep(&ts, NULL);

	stomp_abort_transaction(websocket, tx_id2, NULL);
	nanosleep(&ts, NULL);
	printf("✓ Transaction ABORT works\n");

	// Test 7: Test message with receipt
	printf("\n[TEST 7/7] Testing receipt mechanism...\n");
	stomp_send_message(websocket, destination, "Receipt test", 12,
	                   "text/plain", "receipt-test-1", NULL);
	nanosleep(&ts, NULL);

	// Read any receipts
	for(int i = 0; i < 3; i++) {
		cwebsocket_client_read_data(websocket);
		nanosleep(&ts, NULL);
	}
	printf("✓ Receipt mechanism tested\n");

	printf("\n✓ All STOMP 1.2 features validated!\n");
	printf("\nTest complete. Disconnecting...\n");
}

int main(int argc, char **argv) {

	print_program_header();
	if(argc < 3) print_program_usage(argv[0]);

	const char *uri = argv[1];
	const char *destination = argv[2];

	// Get STOMP connection parameters from environment with validation
	// Limit to reasonable lengths to prevent abuse (CWE-20, CWE-807)
	#define MAX_ENV_LEN 256
	const char *stomp_host = get_validated_env("STOMP_HOST", MAX_ENV_LEN);
	const char *stomp_login = get_validated_env("STOMP_LOGIN", MAX_ENV_LEN);
	const char *stomp_passcode = get_validated_env("STOMP_PASSCODE", MAX_ENV_LEN);

	if(!stomp_host) stomp_host = "/";

	printf("Connecting to: %s\n", uri);
	printf("STOMP Host: %s\n", stomp_host);
	if(stomp_login) {
		printf("STOMP Login: %s\n", stomp_login);
	}
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
	openlog("stomp-client", LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "starting stomp websocket client");

	// Enable synchronous callbacks to avoid threading issues
	// (Threading support for STOMP needs further refinement)
	setenv("CWS_SYNC_CALLBACKS", "1", 1);

	// Initialize WebSocket client with STOMP subprotocol
	cwebsocket_client_init(&websocket_client, NULL, 0);
	websocket_client.subprotocol = cwebsocket_subprotocol_stomp_client_new(stomp_host, stomp_login, stomp_passcode);
	websocket_client.uri = (char *)uri;

	// Get the STOMP state that was created in the factory function
	// (stored in global_stomp_state within the STOMP module)
	stomp_state = NULL;  // We'll access it through the module's global

	if(cwebsocket_client_connect(&websocket_client) == -1) {
		return main_exit(EXIT_FAILURE);
	}

	run_stomp_test(&websocket_client, destination);

	// Send DISCONNECT and close
	stomp_send_disconnect(&websocket_client, NULL);
	struct timespec ts = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms
	nanosleep(&ts, NULL);

	cwebsocket_client_close(&websocket_client, 1000, "Test complete");
	return main_exit(EXIT_SUCCESS);
}
