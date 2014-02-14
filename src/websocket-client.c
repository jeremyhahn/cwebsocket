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
#include "cwebsocket/client.h"

cwebsocket_client websocket_client;

void onopen(cwebsocket_client *websocket) {
	syslog(LOG_DEBUG, "onconnect: websocket file descriptor: %i", websocket->socket);
}

void onmessage(cwebsocket_client *websocket, cwebsocket_message *message) {
	syslog(LOG_DEBUG, "onmessage: socket=%i, opcode=%#04x, payload_len=%zu, payload=%s\n",
			websocket->socket, message->opcode, message->payload_len, message->payload);
}

void onclose(cwebsocket_client *websocket, const char *message) {
	syslog(LOG_DEBUG, "onclose: websocket file descriptor: %i, message: %s", websocket->socket, message);
}

void onerror(cwebsocket_client *websocket, const char *message) {
	syslog(LOG_DEBUG, "onerror: message=%s", message);
}

int main_exit(int exit_status) {
	syslog(LOG_DEBUG, "exiting cwebsocket");
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
			cwebsocket_close(&websocket_client, "SIGINT/SIGTERM");
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
    printf(" \\___/ ____/|__/ \\___//_.___//____/ \\____/\\___/ /_/|_| \\___/\\__/\n");
    printf("\n");
    printf("                                   Copyright (c) 2014 Jeremy Hahn\n");
    printf("                                   mail@jeremyhahn.com           \n");
	printf("\n");
}

void print_program_usage(const char *progname) {

	fprintf(stderr, "usage: [uri]\n");
	fprintf(stderr, "example: %s ws://echo.websocket.org\n\n", progname);
	exit(0);
}

void run_websocket_org_echo_test(cwebsocket_client *websocket) {

	const char *message1 = "WebSocket Works!";
	cwebsocket_write_data(&websocket_client, message1, strlen(message1));
	cwebsocket_read_data(websocket);
}

int main(int argc, char **argv) {

	print_program_header();
	if(argc != 2) print_program_usage(argv[0]);

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
	openlog("cwebsocket", LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "starting cwebsocket client");

	websocket_client.onopen = &onopen;
	websocket_client.onmessage = &onmessage;
	websocket_client.onclose = &onclose;
	websocket_client.onerror = &onerror;

	cwebsocket_init();
	websocket_client.uri = argv[1];
	//websocket_client.flags |= WEBSOCKET_FLAG_AUTORECONNECT;  // OPTIONAL - retry failed connections
	//websocket_client.retry = 5;                              // OPTIONAL - seconds to wait before retrying
	if(cwebsocket_connect(&websocket_client) == -1) {
		return main_exit(EXIT_FAILURE);
	}

	run_websocket_org_echo_test(&websocket_client);

	cwebsocket_close(&websocket_client, "main: run loop complete");
	return main_exit(EXIT_SUCCESS);
}
