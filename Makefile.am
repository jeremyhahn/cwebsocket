AUTOMAKE_OPTIONS = foreign

COMMON = src/cwebsocket/utf8.h src/cwebsocket/utf8.c src/cwebsocket/common.h src/cwebsocket/common.c
ECHO_CLIENT = src/cwebsocket/subprotocol/echo/echo_client.h src/cwebsocket/subprotocol/echo/echo_client.c
ECHO_SERVER = src/cwebsocket/subprotocol/echo/echo_server.h src/cwebsocket/subprotocol/echo/echo_server.c

bin_PROGRAMS = websocket-client websocket-server websocket-testsuite
websocket_client_SOURCES = $(ECHO_CLIENT) $(COMMON) src/cwebsocket/client.h src/cwebsocket/client.c src/websocket-client.c
websocket_server_SOURCES = $(ECHO_SERVER) $(COMMON) src/cwebsocket/server.h src/cwebsocket/server.c src/websocket-server.c
websocket_testsuite_SOURCES = $(COMMON) src/cwebsocket/client.h src/cwebsocket/client.c src/websocket-testsuite.c

AM_CFLAGS= -Wall

if DEBUG
  AM_CFLAGS += -g3
else
  AM_CFLAGS += -O3
endif

clean:
	rm -rf .gitignore vgcore.* autoscan.log config.h.in config.h config.cache configure install-sh aclocal.m4 autom4te.cache/ config.log config.status Debug/ depcomp .deps/ m4/ Makefile Makefile.in missing stamp-h1 *.o src/*.o *~ websocket-client websocket-server websocket-testsuite
