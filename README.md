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

	./websocket-client ws://echo.websocket.org

