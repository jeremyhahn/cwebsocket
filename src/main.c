#include <stdio.h>
#include <signal.h>
#include "client.h"

#define APPNAME "cwebsocket"

int WEBSOCKET_FD;

void main_exit(int exit_status);

void signal_handler(int sig) {

	switch(sig) {
		case SIGHUP:
			syslog(LOG_DEBUG, "Received SIGHUP signal");
			// TODO Reload config and reopen files
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_INFO, "Caught SIGINT/SIGTERM - terminating");
			websocket_close(WEBSOCKET_FD);
			main_exit(EXIT_SUCCESS);
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
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

void on_connect(int fd) {
	char str_fd[2];
	sprintf(str_fd, "%d", fd);
	syslog(LOG_DEBUG, "on_connect_callback: websocket file descriptor: %s", str_fd);
	syslog(LOG_DEBUG, "on_connect_callback: bytes=%zu", strlen(str_fd));
}

int on_message(const char *message) {
	syslog(LOG_DEBUG, "on_message_callback: data=%s", message);
	syslog(LOG_DEBUG, "on_message_callback: bytes=%zu", strlen(message));
	return 0;
}

void on_close_callback() {
	syslog(LOG_DEBUG, "on_close_callback");
}

int main(int argc, char **argv) {

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

	if(argc != 4) {
		fprintf(stderr, "usage: [hostname] [port] [resource]\n");
		exit(0);
	}

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

	WEBSOCKET_FD = websocket_connect(argv[1], argv[2], argv[3], &on_connect);
	//WEBSOCKET_FD = websocket_connect(argv[1], argv[2], argv[3], NULL);
	if(WEBSOCKET_FD == -1) {
    	main_exit(EXIT_FAILURE);
    }

	while(1) {

		syslog(LOG_DEBUG, "main: calling websocket_read");

		int callback_return_value = websocket_read_data(WEBSOCKET_FD, &on_message);
		//int callback_return_value = websocket_read_data(websocket, NULL);
		if(callback_return_value == -1) {
			syslog(LOG_ERR, "The connection to the server was broken or the handler was unable to process the incoming data.");
			websocket_close(WEBSOCKET_FD);
			main_exit(EXIT_FAILURE);
			break;
		}
	}

	websocket_close(WEBSOCKET_FD);
    main_exit(EXIT_SUCCESS);
    return EXIT_SUCCESS;
}

void main_exit(int exit_status) {
	syslog(LOG_DEBUG, "Exiting cwebsocket");
	closelog();
	exit(exit_status);
}
