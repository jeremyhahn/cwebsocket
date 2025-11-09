[logo]: https://github.com/jeremyhahn/cwebsocket/raw/master/websocket.png "cwebsocket"

# ![alt text][logo] cwebsocket

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/jeremyhahn/cwebsocket/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![WebSocket](https://img.shields.io/badge/RFC%206455-compliant-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc6455)

A portable, high-performance WebSocket client library written in C, designed for embedded systems and production environments.

## Features

### WebSocket Protocol (RFC 6455)

Complete implementation of the WebSocket protocol with 100% Autobahn test suite compliance.

- Binary and text frame support
- Fragmentation and control frames (ping/pong/close)
- SSL/TLS support (wss://)
- Permessage-deflate compression
- Multi-threaded client support
- UTF-8 validation with overlong encoding detection

### Subprotocols

**Echo** - Simple echo subprotocol for testing and examples

**STOMP 1.2** - Streaming Text Oriented Messaging Protocol
- Frame encoding and decoding
- Header processing
- Binary message support

**MQTT 5.0** - Message Queuing Telemetry Transport with enhanced authentication
- All packet types (CONNECT, PUBLISH, SUBSCRIBE, PUBACK, PUBREC, PUBREL, PUBCOMP, DISCONNECT, AUTH)
- QoS levels 0, 1, and 2
- Retained messages
- Topic aliases for bandwidth optimization
- SCRAM-SHA-256 enhanced authentication (RFC 5802/7677)
- Subscription options
- Keep-alive with automatic PINGREQ/PINGRESP
- Session persistence
- Flow control and packet ID management
- Property system (38 property types)


## Building

Dependencies: autoconf, automake, libtool, libssl-dev, zlib1g-dev

```bash
./autogen.sh
./configure
make
sudo make install
```

Build options:

```bash
./configure --enable-threads=no   # Disable multi-threading
./configure --enable-ssl=no       # Disable SSL/TLS support
```

## Usage

### WebSocket Client

```bash
./websocket-client wss://echo.websocket.org
```

### STOMP Client

```bash
./stomp-client ws://localhost:61614
```

### MQTT Client

```bash
./mqtt-client ws://localhost:8083/mqtt
```

## Testing

Run unit tests:

```bash
make test
```

Run integration tests:

```bash
make test-integration
```

Component-specific tests:

```bash
make test-websocket     # WebSocket unit and integration tests
make test-stomp         # STOMP integration tests
make test-mqtt          # MQTT unit and integration tests
make test-mqtt-auth     # MQTT SCRAM-SHA-256 authentication tests
```

Quality assurance:

```bash
make qa                 # Run full QA suite (build, test, valgrind, static analysis, security scan)
make valgrind           # Memory leak detection
make static-analysis    # cppcheck analysis
make security-scan      # flawfinder security scan
```

## Support

Please consider supporting this project for ongoing success and sustainability. I'm a passionate open source contributor making a professional living creating free, secure, scalable, robust, enterprise grade, distributed systems and cloud native solutions.

I'm also available for international consulting opportunities. Please let me know how I can assist you or your organization in achieving your desired security posture and technology goals.

https://github.com/sponsors/jeremyhahn

https://www.linkedin.com/in/jeremyhahn