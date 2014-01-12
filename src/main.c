#include <stdio.h>
#include <signal.h>
#include "cwebsocket.h"

int WEBSOCKET_FD;
int WEBSOCKET_RUNNING;
cwebsocket websocket;

int main_exit(int exit_status) {
	syslog(LOG_DEBUG, "Exiting cwebsocket");
	closelog();
	return exit_status;
}

void signal_handler(int sig) {
	switch(sig) {
		case SIGHUP:
			syslog(LOG_DEBUG, "Received SIGHUP signal");
			// Reload config and reopen files
			break;
		case SIGINT:
		case SIGTERM:
			syslog(LOG_DEBUG, "SIGINT/SIGTERM");
			WEBSOCKET_RUNNING = 0;
			#ifdef THREADED
			cwebsocket_message message;
			message.opcode = TEXT_FRAME;
			message.payload = "SIGINT/SIGTERM";
			message.payload_len = strlen(message.payload);
			cwebsocket_close(&websocket, &message);
			main_exit(EXIT_SUCCESS);
			#endif
			break;
		default:
			syslog(LOG_WARNING, "Unhandled signal %s", strsignal(sig));
			break;
	}
}

int is_valid_arg(const char *string) {
	int i=0;
	for(i=0; i < strlen(string); i++) {
		if(!isalnum(string[i]) && string[i] != '/' && string[i] != '.' && string[i] != '_' && string[i] != '-') {
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

void create_mock_metrics(char *metrics) {

	int min = 1;
	int max = 100;
	int max2 = 8000;
	char metricbuf[255];

	sprintf(metricbuf, "rpm %i,itt %i,mrp %i,be %i,pwd %i,toa %i,cf %i,afc1 %i,afl1 %i,ma %i,eld %i,fkc %i,flkc %i,iam %i",
			rand()%(max2-min + 1) + min, rand()%(max-min + 1) + min, rand()%(max-min + 1) + min, rand()%(max-min + 1) + min,
			rand()%(max-min + 1) + min, rand()%(max-min + 1) + min, rand()%(max-min + 1) + min, rand()%(max-min + 1) + min,
			rand()%(max-min + 1) + min, rand()%(max-min + 1) + min, rand()%(max-min + 1) + min, rand()%(max-min + 1) + min,
			rand()%(max-min + 1) + min, rand()%(max-min + 1) + min);

	memcpy(metrics, metricbuf, 255);
}

void on_connect(cwebsocket *websocket) {
	syslog(LOG_DEBUG, "on_connect: websocket file descriptor: %i", websocket->sock_fd);
}

void on_message(cwebsocket *websocket, cwebsocket_message *message) {
	#ifdef __arm__
	syslog(LOG_DEBUG, "on_message: cwebsocket_message: opcode=%#x, payload_len=%i, payload=%s",
			message->opcode, message->payload_len, message->payload);
	#else
	syslog(LOG_DEBUG, "on_message: cwebsocket_message: opcode=%#x, payload_len=%zu, payload=%s",
			message->opcode, message->payload_len, message->payload);
	#endif
}

void on_close(cwebsocket *websocket, cwebsocket_message *message) {
	if(message != NULL) {
		syslog(LOG_DEBUG, "on_close: file descriptor: %i, %s", websocket->sock_fd, message->payload);
	}
}

void on_error(cwebsocket *websocket, const char *message) {
	syslog(LOG_DEBUG, "on_error: message=%s", message);
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
	openlog("cwebsocket", LOG_CONS | LOG_PERROR, LOG_USER);
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

	websocket.on_connect = &on_connect;
	websocket.on_message = &on_message;
	websocket.on_close = &on_close;
	websocket.on_error = &on_error;

	cwebsocket_connect(&websocket, argv[1], argv[2], argv[3]);

	if(websocket.sock_fd == -1) {
		printf("websocket: sock_fd=%i\n", websocket.sock_fd);
		main_exit(EXIT_FAILURE);
    }

	WEBSOCKET_RUNNING = 1;
	while(WEBSOCKET_RUNNING == 1) {
		syslog(LOG_DEBUG, "main: calling websocket_read");
		cwebsocket_read_data(&websocket);
	}

	/*
	uint64_t messages_sent = 0;
	char metrics[255];

	time_t start_time, finish_time;
	start_time = time(0);

	WEBSOCKET_RUNNING = 1;
	while(WEBSOCKET_RUNNING == 1) {
		create_mock_metrics(metrics);
		//printf("Metrics: %s\n", metrics);
		cwebsocket_write_data(WEBSOCKET_FD, metrics, strlen(metrics));
		sleep(1);
		messages_sent++;
	}

	finish_time = time(0);
	printf("Sent %lld messages in %i seconds\n", (long long)messages_sent, (int) (finish_time-start_time));
	*/

	cwebsocket_message message;
	message.opcode = TEXT_FRAME;
	message.payload = "Main event loop complete";
	message.payload_len = strlen(message.payload);

	cwebsocket_close(&websocket, &message);
    return main_exit(EXIT_SUCCESS);
}
