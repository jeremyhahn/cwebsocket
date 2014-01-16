# cwebsocket

###### Fast, lightweight websocket server/client.

cwebsocket is currently in an ALPHA state. You may encounter bugs. Successful tests have been conducted on the following architectures:

1. [x86](http://en.wikipedia.org/wiki/X86)
2. [x86_64](http://en.wikipedia.org/wiki/X86-64)
3. [ARM](http://en.wikipedia.org/wiki/ARM_architecture)

cwebsocket is compliant with the following standards:

1. [ANSI C](http://en.wikipedia.org/wiki/ANSI_C)
2. [POSIX](http://en.wikipedia.org/wiki/C_POSIX_library)
3. [RFC 6455](http://tools.ietf.org/html/rfc6455)

### Build

By default, cwebsocket is built for multi-threaded 64-bit architectures.

	make

To build without threads:

	make NOTHREADS=1

To build for x86 32-bit architecture:

	make PLATFORM=x86

To build for ARM architecture:

	make PLATFORM=arm

> NOTE: 32-bit architectures are limited to a max payload size of 65536 byte frames.

### Client

The websocket client is able to connect and exchange data with any RFC 6455 compliant server.

	./websocket-client ws://echo.websocket.org

