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
#include "cwebsocket/server.h"

cwebsocket_server websocket_server;

void signal_handler(int sig) {
	switch(sig) {
		case SIGHUP:
			syslog(LOG_DEBUG, "Received SIGHUP signal");
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_DEBUG, "SIGINT/SIGTERM");
			exit(0);
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}

void print_program_header() {

	fprintf(stderr, "\n");
	fprintf(stderr, " cwebsocket: A fast, lightweight websocket client/server\n");
	fprintf(stderr, "                          Copyright (c) 2014 Jeremy Hahn\n");
	fprintf(stderr, "\n");
}

void print_program_usage(const char *progname) {

	fprintf(stderr, "usage: %s -p 8080\n\n", progname);
	exit(0);
}

int main(int argc, char **argv) {

	websocket_server.port = 8080;

	// Parse command line arguments
	size_t i;
	for (i = 0; i < argc; i++) {
		char const *option =  argv[i];
		if(option[0] == '-') {
			switch (option[1]) {
				case 'p':
					websocket_server.port = atoi(argv[i+1]);
					break;
				default:
					printf("invalid option: %s", option);
					break;
			}
		}
	}

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
	syslog(LOG_DEBUG, "starting cwebsocket server on port %i", websocket_server.port);

	cwebsocket_connect(&websocket_server);
	cwebsocket_close(&websocket_server);

	return EXIT_SUCCESS;
}
