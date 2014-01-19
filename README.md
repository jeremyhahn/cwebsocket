[logo]: https://github.com/jeremyhahn/cwebsocket/raw/master/websocket.png "cwebsocket"

# ![alt text][logo] cwebsocket

###### Fast, lightweight websocket server/client.

The goal of cwebsocket is to provide a simple, lightweight, high performance websocket solution that's
efficient enough to run well on low power embedded systems.

cwebsocket is currently in a development state. You may encounter bugs. Report them for a timely fix.

Successful tests have been conducted on the following architectures:

1. [x86](http://en.wikipedia.org/wiki/X86)
2. [x86_64](http://en.wikipedia.org/wiki/X86-64)
3. [ARM](http://en.wikipedia.org/wiki/ARM_architecture)

cwebsocket is compliant with the following standards:

1. [ANSI C](http://en.wikipedia.org/wiki/ANSI_C)
2. [POSIX](http://en.wikipedia.org/wiki/C_POSIX_library)
3. [RFC 6455](http://tools.ietf.org/html/rfc6455)

### Build

By default, cwebsocket is built with SSL support for multi-threaded, 64-bit architectures. To build, run:

	make

To build a shared object library (libcwebsocket.so), run:

	make so

##### Customizing/Optimizing Build

Without threads:

	make NOTHREADS=1

Target x86 32-bit architecture:

	make PLATFORM=x86

Target ARM architecture:

	make PLATFORM=arm

> NOTE: 32-bit architectures are limited to a max payload size of 65536 byte frames.

Without SSL:

	make NOSSL=1

### Client

The websocket client is able to connect and exchange data with any RFC 6455 compliant server.

##### Binary Example

	./websocket-client ws://echo.websocket.org

	./websocket-client wss://echo.websocket.org

##### Code Sample

```C
#include <stdio.h>
#include <signal.h>
#include "cwebsocket.h"

cwebsocket_client websocket;

void onopen(cwebsocket_client *websocket) {
	syslog(LOG_DEBUG, "onconnect: websocket file descriptor: %i", websocket->socket);
}

void onmessage(cwebsocket_client *websocket, cwebsocket_message *message) {

	syslog(LOG_DEBUG, "onmessage: socket_fd=%i, opcode=%#04x, payload_len=%zu, payload=%s\n",
			websocket->socket, message->opcode, message->payload_len, message->payload);

}

void onclose(cwebsocket_client *websocket, const char *message) {
	if(message != NULL) {
		syslog(LOG_DEBUG, "onclose: websocket file descriptor: %i, %s", websocket->socket, message);
	}
}

void onerror(cwebsocket_client *websocket, const char *message) {
	syslog(LOG_DEBUG, "onerror: message=%s", message);
}

int main(int argc, char **argv) {

	setlogmask(LOG_UPTO(LOG_DEBUG)); // LOG_INFO, LOG_DEBUG
	openlog("cwebsocket", LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "starting cwebsocket");

	websocket.onopen = &onopen;
	websocket.onmessage = &onmessage;
	websocket.onclose = &onclose;
	websocket.onerror = &onerror;

	if(cwebsocket_connect(&websocket, argv[1]) == -1) {
		perror("unable to connect to remove websocket server");
		return -1;
	}

	const char *message = "WebSocket Works!";
	cwebsocket_write_data(&websocket, message, strlen(message));
	cwebsocket_read_data(&websocket);

	cwebsocket_close(&websocket, "main: cwebsocket exiting");
	return EXIT_SUCCESS;
}
```
