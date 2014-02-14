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
	fprintf(stderr, "usage: %s -p 8080\n\n", progname);
	exit(0);
}

int main(int argc, char **argv) {

	print_program_header();

	cwebsocket_server *server = cwebsocket_server_new();
	server->port = 8080;

	size_t i;
	for(i = 0; i < argc; i++) {
		char const *option =  argv[i];
		if(option[0] == '-') {
			switch(option[1]) {
				case 'p':
					server->port = atoi(argv[i+1]);
					if(server->port < 0 || server->port > 65535) {
						perror("invalid port number\n");
						return -1;
					}
					break;
				case 'c':
					server->cores = atoi(argv[i+1]);
					if(server->cores < 0) {
						perror("server cores must be greater than zero\n");
						return -1;
					}
					break;
				default:
					printf("invalid option: %s\n", option);
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
	syslog(LOG_DEBUG, "starting cwebsocket server on port %i", server->port);

	cwebsocket_server_connect(server);
	cwebsocket_server_close(server);
	free(server);

	return EXIT_SUCCESS;
}
