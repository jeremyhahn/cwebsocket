[logo]: https://github.com/jeremyhahn/cwebsocket/raw/master/websocket.png "cwebsocket"

# ![alt text][logo] cwebsocket

###### High performance websocket client/server

The goal of cwebsocket is to provide a portable, high performance websocket client/server, especially on low power embedded systems.

cwebsocket is currently in a development state. You may encounter bugs. Report them for a timely fix.

Successful tests have been conducted on the following architectures:

1. [x86](http://en.wikipedia.org/wiki/X86)
2. [x86_64](http://en.wikipedia.org/wiki/X86-64)
3. [ARM](http://en.wikipedia.org/wiki/ARM_architecture)

cwebsocket is compliant with the following standards:

1. [ANSI C](http://en.wikipedia.org/wiki/ANSI_C)
2. [POSIX](http://en.wikipedia.org/wiki/C_POSIX_library)
3. [RFC 6455](http://tools.ietf.org/html/rfc6455)

### Dependencies

1. autoconf
2. automake
3. libtool
4. libssl-dev
5. libev-dev

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

	./websocket-client ws://echo.websocket.org
	./websocket-client wss://echo.websocket.org

### Dockerized Tests

All tests run inside a Docker container — nothing is installed on the host.

- Build the test image:

	make docker-build

- Run unit tests inside the container:

	make test

- Run the Autobahn integration suite (reports in `test/autobahn/reports/clients` on the host):

	make integration-test

- Open a shell in the container (optional):

	make docker-shell

Note: Integration tests start the Autobahn fuzzing server inside the container and run `websocket-testsuite` against it. Reports are written to the mounted host directory `test/autobahn/reports/clients`.

### TODO

1. More testing on various embedded devices
2. Implement pluggable sub-protocols (socketio, WAMP, custom)
3. Implement pluggable extensions on the client per RFC (section 9)
4. Get a basic websocket server developed


## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn
