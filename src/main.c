#include <stdio.h>
#include <signal.h>
#include "cwebsocket.h"

#define APPNAME "cwebsocket"

int WEBSOCKET_FD;

void main_exit(int exit_status);

void signal_handler(int sig) {

	switch(sig) {
		case SIGHUP:
			syslog(LOG_DEBUG, "Received SIGHUP signal");
			// Reload config and reopen files
			break;
		case SIGINT:
		case SIGTERM:
			cwebsocket_close(WEBSOCKET_FD, "SIGINT/SIGTERM");
			main_exit(EXIT_SUCCESS);
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}

void on_connect(int fd) {
	char str_fd[10];
	sprintf(str_fd, "%d", fd);
	syslog(LOG_DEBUG, "on_connect: websocket file descriptor: %i", fd);
	syslog(LOG_DEBUG, "on_connect: bytes=%zu", strlen(str_fd));
}

int on_message(int fd, const char *message) {
	syslog(LOG_DEBUG, "on_message: data=%s", message);
	syslog(LOG_DEBUG, "on_message: bytes=%zu", strlen(message));
	return 0;
}

void on_close(int fd, const char *message) {
	if(message != NULL) {
		syslog(LOG_DEBUG, "on_close: %s", message);
	}
	syslog(LOG_DEBUG, "on_close: websocket file descriptor: %i", fd);
}

int is_valid_arg(const char *string) {
	int i=0;
	for(i=0; i < strlen(string); i++) {
		if(!isalnum(string[i]) && string[i] != '/') {
			return 0;
		}
	}
	return 1;
}

void print_program_header() {

	fprintf(stderr, "****************************************************************************\n");
	fprintf(stderr, "* cwebsocket: A fast, lightweight websocket client/server                  *\n");
	fprintf(stderr, "*                                                                          *\n");
	fprintf(stderr, "* Copyright (c) 2014 Jeremy Hahn                                           *\n");
	fprintf(stderr, "*                                                                          *\n");
	fprintf(stderr, "* cwebsocket is free software: you can redistribute it and/or modify       *\n");
	fprintf(stderr, "* it under the terms of the GNU Lesser General Public License as published *\n");
	fprintf(stderr, "* by the Free Software Foundation, either version 3 of the License, or     *\n");
	fprintf(stderr, "* (at your option) any later version.                                      *\n");
	fprintf(stderr, "*                                                                          *\n");
	fprintf(stderr, "* cwebsocket is distributed in the hope that it will be useful,            *\n");
	fprintf(stderr, "* but WITHOUT ANY WARRANTY; without even the implied warranty of           *\n");
	fprintf(stderr, "* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *\n");
	fprintf(stderr, "* GNU Lesser General Public License for more details.                      *\n");
	fprintf(stderr, "*                                                                          *\n");
	fprintf(stderr, "* You should have received a copy of the GNU Lesser General Public License *\n");
	fprintf(stderr, "* along with cwebsocket.  If not, see <http://www.gnu.org/licenses/>.      *\n");
	fprintf(stderr, "****************************************************************************\n");
	fprintf(stderr, "\n");
}

void print_program_usage() {

	print_program_header();
	fprintf(stderr, "usage: [hostname] [port] [path]\n");
	exit(0);
}

int main(int argc, char **argv) {

	print_program_header();

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
	openlog(APPNAME, LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "Starting cwebsocket");

	if(argc != 4) print_program_usage();

    int port = atoi(argv[2]);
	if(port > 65536 || port < 0 ) {
		syslog(LOG_ERR, "Invalid port number\n");
		exit(0);
	}
	if(!is_valid_arg(argv[1])) {
		syslog(LOG_ERR, "Invalid hostname");
		exit(0);
	}
	if(!is_valid_arg(argv[3])) {
		syslog(LOG_ERR, "Invalid resource");
		exit(0);
	}

	on_connect_callback_ptr = &on_connect;
	on_message_callback_ptr = &on_message;
	on_close_callback_ptr = &on_close;

	WEBSOCKET_FD = cwebsocket_connect(argv[1], argv[2], argv[3]);
	if(WEBSOCKET_FD == -1) {
    	main_exit(EXIT_FAILURE);
    }

	char *data_to_write = "testme";
	ssize_t bytes_written = cwebsocket_write_data(WEBSOCKET_FD, data_to_write, 6);
	syslog(LOG_DEBUG, "Wrote %zd bytes to the socket", bytes_written);

	sleep(2);

	/*
	while(1) {

		syslog(LOG_DEBUG, "main: calling websocket_read");

		int callback_return_value = websocket_read_data(WEBSOCKET_FD);
		if(callback_return_value == -1) {
			syslog(LOG_ERR, "Connection broken or unable to process ingress data");
			websocket_close(WEBSOCKET_FD, NULL);
			main_exit(EXIT_FAILURE);
			break;
		}
	}*/

	cwebsocket_close(WEBSOCKET_FD, "Main event loop complete");
    main_exit(EXIT_SUCCESS);
    return EXIT_SUCCESS;
}

void main_exit(int exit_status) {
	syslog(LOG_DEBUG, "Exiting cwebsocket");
	closelog();
	exit(exit_status);
}
