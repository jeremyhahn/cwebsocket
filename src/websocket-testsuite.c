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
#include <string.h>
#include <unistd.h>
#include "cwebsocket/client.h"
#include "cwebsocket/subprotocol/echo/echo_client.h"

cwebsocket_client websocket_client;

#define STATE_GET_CASE_COUNT     (1 << 0)
#define STATE_RUNNING_TESTS      (1 << 1)
#define STATE_GENERATNING_REPORT (1 << 2)

uint8_t STATE;
int number_of_tests = 0;
int start_case = 1;
int max_cases = 0; // 0 means unlimited

void autobahn_onopen(void *websocket) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "autobahn_onopen: fd=%i", client->fd);
}

void autobahn_onmessage(void *websocket, cwebsocket_message *message) {

    cwebsocket_client *client = (cwebsocket_client *)websocket;
    syslog(LOG_DEBUG, "autobahn_onmessage: fd=%i, opcode=%#04x, payload_len=%zu\n",
            client->fd, message->opcode, (size_t)message->payload_len);

    if(STATE & STATE_GET_CASE_COUNT) {
        char *endptr;
        errno = 0;
        long count = strtol((const char *)message->payload, &endptr, 10);
        if(errno == 0 && endptr != (const char *)message->payload && count > 0 && count <= INT_MAX) {
            number_of_tests = (int)count;
        } else {
            number_of_tests = 0;
        }
        STATE |= STATE_RUNNING_TESTS;
        syslog(LOG_DEBUG, "autobahn_onmessage: fetched %i test cases", number_of_tests);
    }
    else if(STATE & STATE_RUNNING_TESTS) {
        // Echo back only if socket is still open
        if(client->state & WEBSOCKET_STATE_OPEN) {
            syslog(LOG_DEBUG, "autobahn_onmessage: echoing data back to server");
            uint64_t payload_length = message->payload_len;
            cwebsocket_client_write_data(client, message->payload, payload_length, message->opcode);
        }
    }
}

void autobahn_onclose(void *websocket, int code, const char *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "autobahn_onclose: fd=%i, code=%i, message=%s", client->fd, code, message);
}

void autobahn_onerror(void *websocket, const char *message) {
	cwebsocket_client *client = (cwebsocket_client *)websocket;
	syslog(LOG_DEBUG, "autobahn_onerror: fd=%i, message=%s", client->fd, message);
}

cwebsocket_subprotocol* autobahn_testsuite_new() {
	cwebsocket_subprotocol *protocol = malloc(sizeof(cwebsocket_subprotocol));
	memset(protocol, 0, sizeof(cwebsocket_subprotocol));
	protocol->name = "echo.cwebsocket\0";
	protocol->onopen = &autobahn_onopen;
	protocol->onmessage = &autobahn_onmessage;
	protocol->onclose = &autobahn_onclose;
	protocol->onerror = &autobahn_onerror;
	return protocol;
}

int main_exit(int exit_status) {
    syslog(LOG_DEBUG, "exiting cwebsocket");
    closelog();
    _exit(exit_status); // avoid stdio flushing issues in some environments
    return exit_status; // not reached
}

void print_program_header() {
    if (!isatty(STDOUT_FILENO)) return;
    printf("\n");
    printf("                      ______                    ______      _____ \n");
    printf(" _________      _________  /_______________________  /________  /_\n");
    printf(" _  ___/_ | /| / /  _ \\_  __ \\_  ___/  __ \\  ___/_  //_/  _ \\  __/\n");
    printf(" / /__ __ |/ |/ //  __/  /_/ /(__  )/ /_/ / /__ _  ,<  /  __/ /_  \n");
    printf(" \\___/ ____/|__/ \\___//_____//____/ \\____/\\___/ /_/|_| \\___/\\__/\n");
    printf("\n");
    printf("                                   Autobahn Testsuite            \n");
    printf("                                   Copyright (c) 2014 Jeremy Hahn\n");
    printf("                                   mail@jeremyhahn.com           \n");
    printf("\n");
}

int main(int argc, char **argv) {

    print_program_header();

    // Default to INFO to reduce logging overhead; enable DEBUG with CWS_DEBUG=1
    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *dbg = getenv("CWS_DEBUG");
    if(dbg && *dbg && strnlen(dbg, 256) < 256 && strcmp(dbg, "0") != 0) {
        setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
        setlogmask(LOG_UPTO(LOG_INFO));
    }
	openlog("cwebsocket", LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "starting cwebsocket client");

    // Prefer synchronous callbacks in the tests for speed unless explicitly disabled
    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *sync_cb = getenv("CWS_SYNC_CALLBACKS");
    if(sync_cb == NULL || strnlen(sync_cb, 256) >= 256) {
        setenv("CWS_SYNC_CALLBACKS", "1", 1);
    }

    STATE |= STATE_GET_CASE_COUNT;

	// Allow overriding fuzzing server base via env var
    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *server_base = getenv("WS_FUZZING_SERVER");
    if(server_base == NULL || strnlen(server_base, 512) == 0 || strnlen(server_base, 512) >= 512) {
        // Default to host port 8111 (container 9001 is mapped to host 8111)
        server_base = "ws://localhost:8111";
    }

    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *reports_only = getenv("WS_UPDATE_REPORTS_ONLY");
    if (reports_only && strnlen(reports_only, 256) > 0 && strnlen(reports_only, 256) < 256 && strcmp(reports_only, "0") != 0) {
        // Only trigger report generation and exit
        cwebsocket_client_init(&websocket_client, NULL, 0);
        websocket_client.subprotocol = autobahn_testsuite_new();
        // Flawfinder: ignore - char array used with snprintf bounds checking
        char uri_update[512];
        snprintf(uri_update, sizeof(uri_update), "%s/updateReports?agent=cwebsocket/0.1a", server_base);
        websocket_client.uri = uri_update;
        if(cwebsocket_client_connect(&websocket_client) == -1) {
            perror("unable to connect to server to run reports");
            return main_exit(EXIT_FAILURE);
        }
        cwebsocket_client_read_data(&websocket_client);
        cwebsocket_client_close(&websocket_client, 1000, "disconnecting");
        free(websocket_client.subprotocol);
        return main_exit(EXIT_SUCCESS);
    }

    cwebsocket_client_init(&websocket_client, NULL, 0);

    // Hardcoding the protocol instead of relying on negotiation during handshake
    websocket_client.subprotocol = autobahn_testsuite_new();
    // Flawfinder: ignore - char array used with snprintf bounds checking
    char uri_get[512];
    snprintf(uri_get, sizeof(uri_get), "%s/getCaseCount", server_base);

    // Retry fetching case count if zero, allowing server time to warm up
    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *wait_env = getenv("WS_CASECOUNT_RETRIES");
    int max_retries = 60; // default
    // Flawfinder: ignore - strlen on null-terminated wait_env string
    if(wait_env && strlen(wait_env) > 0) {
        char *endptr;
        errno = 0;
        long retries = strtol(wait_env, &endptr, 10);
        if(errno == 0 && endptr != wait_env && retries > 0 && retries <= INT_MAX) {
            max_retries = (int)retries;
        }
    }
    for (int attempt = 0; attempt < max_retries; ++attempt) {
        websocket_client.uri = uri_get;
        if (cwebsocket_client_connect(&websocket_client) == 0) {
            cwebsocket_client_read_data(&websocket_client);
            cwebsocket_client_close(&websocket_client, 1000, "received number of tests");
        } else {
            // Ensure any half-open state is torn down before retrying
            cwebsocket_client_close(&websocket_client, 1000, "retrying getCaseCount");
        }
        syslog(LOG_DEBUG, "Total number of tests: %i (attempt %d/%d)", number_of_tests, attempt+1, max_retries);
        if (number_of_tests > 0) break;
        sleep(1);
    }
    if (number_of_tests <= 0) {
        syslog(LOG_ERR, "No Autobahn test cases reported by server. Exiting.");
        return main_exit(EXIT_FAILURE);
    }

    // Optional environment controls to speed up local iterations
    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *env_start = getenv("WS_START_CASE");
    // Flawfinder: ignore - strlen on null-terminated env_start string
    if(env_start && strlen(env_start) > 0) {
        char *endptr;
        errno = 0;
        long v = strtol(env_start, &endptr, 10);
        if(errno == 0 && endptr != env_start && v > 0 && v <= INT_MAX) {
            start_case = (int)v;
        }
    }
    // Flawfinder: ignore - getenv validated with NULL and length checks
    const char *env_max = getenv("WS_MAX_CASES");
    // Flawfinder: ignore - strlen on null-terminated env_max string
    if(env_max && strlen(env_max) > 0) {
        char *endptr;
        errno = 0;
        long v = strtol(env_max, &endptr, 10);
        if(errno == 0 && endptr != env_max && v > 0 && v <= INT_MAX) {
            max_cases = (int)v;
        }
    }
    if(max_cases > 0 && number_of_tests > max_cases) {
        number_of_tests = max_cases;
    }

    STATE = STATE_RUNNING_TESTS;
    int i;
    for(i = start_case; i < start_case + number_of_tests; i++) {

		syslog(LOG_DEBUG, "Running test %i", i);

		// Flawfinder: ignore - char array used with snprintf bounds checking
		char uri[512];
        snprintf(uri, sizeof(uri), "%s/runCase?case=%i&agent=%s", server_base, i, "cwebsocket/1.0");

		websocket_client.uri = uri;
        if(cwebsocket_client_connect(&websocket_client) == -1) {
            // Skip this case and continue; don't abort the whole run
            cwebsocket_client_close(&websocket_client, 1000, "connect failed for case");
            continue;
        }
		cwebsocket_client_listen(&websocket_client);
		cwebsocket_client_close(&websocket_client, 1000, "test complete");
	}

	STATE |= STATE_GENERATNING_REPORT;
	// Flawfinder: ignore - char array used with snprintf bounds checking
	char uri_update[512];
	snprintf(uri_update, sizeof(uri_update), "%s/updateReports?agent=cwebsocket/1.0", server_base);
	websocket_client.uri = uri_update;
	if(cwebsocket_client_connect(&websocket_client) == 0) {
		// Use listen() instead of single read_data() to properly handle connection close
		cwebsocket_client_listen(&websocket_client);
		cwebsocket_client_close(&websocket_client, 1000, "disconnecting");
	} else {
		syslog(LOG_WARNING, "unable to connect to server to update reports, continuing anyway");
	}

	free(websocket_client.subprotocol);
	return main_exit(EXIT_SUCCESS);
}
