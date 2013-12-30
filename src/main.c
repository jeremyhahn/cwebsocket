#include <stdio.h>
#include <signal.h>
#include "client.h"

#define APPNAME "cwebsocket"

void main_exit(int exit_status);

void signal_handler(int sig) {

	switch(sig) {
		case SIGHUP:
			syslog(LOG_WARNING, "Received SIGHUP signal.");
			// TODO Reload config and reopen files
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_INFO, "Caught SIGINT/SIGTERM - terminating");
			websocket_close();
			main_exit(EXIT_SUCCESS);
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}

int custom_message_handler(const char *message) {
	const char *custom_message_header = "Custom message handler: \n";
	int custom_message_len = strlen(custom_message_header)+strlen(message);
	char *custom_message[custom_message_len];
	strcpy(custom_message, custom_message_header);
	strcat(custom_message, message);
	write(1, custom_message, custom_message_len);
	free(message);
	return custom_message_len;
}

int main(int argc, char **argv) {

	struct sigaction newSigAction;
	sigset_t newSigSet;

	/* Set signal mask - signals we want to block */
	sigemptyset(&newSigSet);
	sigaddset(&newSigSet, SIGCHLD);  /* ignore child - i.e. we don't need to wait for it */
	sigaddset(&newSigSet, SIGTSTP);  /* ignore Tty stop signals */
	sigaddset(&newSigSet, SIGTTOU);  /* ignore Tty background writes */
	sigaddset(&newSigSet, SIGTTIN);  /* ignore Tty background reads */
	sigprocmask(SIG_BLOCK, &newSigSet, NULL);   /* Block the above specified signals */

	/* Set up a signal handler */
	newSigAction.sa_handler = signal_handler;
	sigemptyset(&newSigAction.sa_mask);
	newSigAction.sa_flags = 0;

	/* Signals to handle */
	sigaction(SIGHUP, &newSigAction, NULL);     /* catch hangup signal */
	sigaction(SIGTERM, &newSigAction, NULL);    /* catch term signal */
	sigaction(SIGINT, &newSigAction, NULL);     /* catch interrupt signal */

	/* Debug logging
	setlogmask(LOG_UPTO(LOG_DEBUG));
	openlog(DAEMON_NAME, LOG_CONS, LOG_USER);
	*/

	/* Logging */
	setlogmask(LOG_UPTO(LOG_DEBUG)); // LOG_INFO, LOG_DEBUG
	openlog(APPNAME, LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "Starting application");

	int port;
	char *host;

	if(argc != 3) {
		fprintf(stderr, "usage: hostname port\n");
		exit(0);
	}

    port = atoi(argv[2]);
	host = argv[1];

	if(port > 65536 || port < 0 ) {
		fprintf(stderr, "Invalid port number\n");
		exit(0);
	}

	int websocket = websocket_connect(host, argv[2]);
	if(websocket == -1) {
		syslog(LOG_ERR, "Unable to connect to the remote server");
    	main_exit(EXIT_FAILURE);
    }

	while(1) {

		syslog(LOG_DEBUG, "main: calling websocket_read");

		int handler_return_value = websocket_read(websocket, &websocket_message_print_handler);

		if(handler_return_value == -1) {
			syslog(LOG_ERR, "The connection to the server was broken or the handler was unable to process the incoming data.");
			websocket_close();
			main_exit(EXIT_FAILURE);
			break;
		}
		// keep running
	}

	websocket_close();

    main_exit(EXIT_SUCCESS);
}

void main_exit(int exit_status) {
	syslog(LOG_DEBUG, "Exiting application");
	closelog();
	exit(exit_status);
}
