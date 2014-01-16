#include <stdio.h>
#include <signal.h>
#include "cwebsocket.h"

cwebsocket_client websocket_client;

int main_exit(int exit_status) {
	syslog(LOG_DEBUG, "exiting cwebsocket");
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

void print_program_usage(const char *progname) {

	fprintf(stderr, "usage: [uri]\n");
	fprintf(stderr, "example: %s ws://echo.websocket.org\n\n", progname);
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

void onopen(cwebsocket_client *websocket) {
	syslog(LOG_DEBUG, "on_connect: websocket file descriptor: %i", websocket->socket);
}

void onmessage(cwebsocket_client *websocket, cwebsocket_message *message) {

#if defined(__arm__ ) || defined(__i386__)
	syslog(LOG_DEBUG, "on_message: socket:%i, opcode=%#04x, payload_len=%i, payload=%s",
			websocket->socket, message->opcode, message->payload_len, message->payload);
#else
	syslog(LOG_DEBUG, "on_message: socket=%i, opcode=%#04x, payload_len=%zu, payload=%s",
			websocket->socket, message->opcode, message->payload_len, message->payload);
#endif
}

void onclose(cwebsocket_client *websocket, const char *message) {
	if(message != NULL) {
		syslog(LOG_DEBUG, "on_close: file descriptor: %i, %s", websocket->socket, message);
	}
}

void onerror(cwebsocket_client *websocket, const char *message) {
	syslog(LOG_DEBUG, "on_error: message=%s", message);
}

void run_websocket_org_echo_test(cwebsocket_client *websocket) {

	const char *message1 = "testme1234testme1234testme1234te";
	cwebsocket_write_data(&websocket_client, message1, strlen(message1));
	cwebsocket_read_data(websocket);
/*
	const char *message2 = "testme1234testme1234testme1234testme1234testme1234testme1234";
	cwebsocket_write_data(&websocket_client, message2, strlen(message2));
	cwebsocket_read_data(websocket);

	const char *message3 = "testme1234testme1234testme1234testme1234testme1234testme1234testme1234testme1234testme1234testme1234testme1234testme1234test123";
	cwebsocket_write_data(&websocket_client, message3, strlen(message3));
	cwebsocket_read_data(websocket);
*/
}

void run_send_metrics(cwebsocket_client *websocket) {

	uint64_t messages_sent = 0;
	char metrics[255];

	time_t start_time, finish_time;
	start_time = time(0);

	do {
		create_mock_metrics(metrics);
		//printf("Metrics: %s\n", metrics);
		cwebsocket_write_data(websocket, metrics, strlen(metrics));
		sleep(1);
		messages_sent++;
	}
	while((websocket_client.state & WEBSOCKET_STATE_OPEN) != 0);

	finish_time = time(0);
	printf("Sent %lld messages in %i seconds\n", (long long)messages_sent, (int) (finish_time-start_time));
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
	syslog(LOG_DEBUG, "starting cwebsocket");

	websocket_client.onopen = &onopen;
	websocket_client.onmessage = &onmessage;
	websocket_client.onclose = &onclose;
	websocket_client.onerror = &onerror;

	if(cwebsocket_connect(&websocket_client, argv[1]) == -1) {
		return main_exit(EXIT_FAILURE);
	}

	run_websocket_org_echo_test(&websocket_client);
	//run_send_metrics(&websocket_client);
	//cwebsocket_listen(&websocket_client);

	cwebsocket_close(&websocket_client, "main run loop complete");
    return main_exit(EXIT_SUCCESS);
}
