[logo]: https://github.com/jeremyhahn/cwebsocket/raw/master/websocket.png "cwebsocket"

# ![alt text][logo] cwebsocket

###### Fast, lightweight websocket server/client.

The goal of cwebsocket is to provide a simple, lightweight, high performance websocket client/server optimized for low power embedded systems.

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

By defaults, cwebsocket is built with multi-threading and SSL support. 

To build, run:

	./autogen.sh
	./configure
	make
	sudo make install

To built without multi-threading:

	./configure --enable-threads=no

To build without SSL:

	./configure --enable-ssl=no

### Client

The websocket client is able to connect and exchange data with any RFC 6455 compliant server.

```C
#include "cwebsocket/client.h"

cwebsocket_client websocket;

void onopen(cwebsocket_client *websocket) {
	syslog(LOG_DEBUG, "onconnect: websocket file descriptor: %i", websocket->socket);
}

void onmessage(cwebsocket_client *websocket, cwebsocket_message *message) {
	syslog(LOG_DEBUG, "onmessage: socket_fd=%i, opcode=%#04x, payload_len=%zu, payload=%s\n",
			websocket->socket, message->opcode, message->payload_len, message->payload);
}

void onclose(cwebsocket_client *websocket, const char *message) {
	syslog(LOG_DEBUG, "onclose: websocket file descriptor: %i, message: %s", websocket->socket, message);
}

void onerror(cwebsocket_client *websocket, const char *message) {
	syslog(LOG_DEBUG, "onerror: message=%s", message);
}

int main(int argc, char **argv) {

	setlogmask(LOG_UPTO(LOG_DEBUG)); // LOG_INFO, LOG_DEBUG
	openlog("cwebsocket", LOG_CONS | LOG_PERROR, LOG_USER);
	syslog(LOG_DEBUG, "starting cwebsocket");

	websocket.uri = argv[1];
	websocket.flags |= WEBSOCKET_FLAG_AUTORECONNECT;  // OPTIONAL - retry failed connections
	websocket.retry = 5;                              // OPTIONAL - seconds to wait before retrying
	websocket.onopen = &onopen;
	websocket.onmessage = &onmessage;
	websocket.onclose = &onclose;
	websocket.onerror = &onerror;
	
	cwebsocket_init();
	if(cwebsocket_connect(&websocket) == -1) {
           perror("unable to connect to remote websocket server");
           return -1;
	}

	const char *message = "WebSocket Works!";
	if(cwebsocket_write_data(&websocket, message, strlen(message)) == -1) {
		perror("unable to write to websocket");
		return -1;
	}

	if(cwebsocket_read_data(&websocket) == -1) {
		perror("unable to read from websocket");
		return -1;
	}

	cwebsocket_close(&websocket, "main: cwebsocket exiting");
	return EXIT_SUCCESS;
}
```

	./websocket-client ws://echo.websocket.org
	./websocket-client wss://echo.websocket.org

### TODO

1. More testing on various embedded devices
2. Implement pluggable sub-protocols (socketio, WAMP, custom)
3. Implement pluggable extensions on the client per RFC (section 9)
4. Get a basic websocket server developed

