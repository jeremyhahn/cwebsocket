AUTOMAKE_OPTIONS = foreign

bin_PROGRAMS = websocket-client websocket-server
websocket_client_SOURCES = src/cwebsocket/subprotocol/syslog_client.h src/cwebsocket/subprotocol/syslog_client.c src/cwebsocket/utf8.h src/cwebsocket/common.h src/cwebsocket/common.c src/cwebsocket/utf8.c src/cwebsocket/client.h src/cwebsocket/client.c src/websocket-client.c
websocket_server_SOURCES = src/cwebsocket/subprotocol/syslog_server.h src/cwebsocket/subprotocol/syslog_server.c src/cwebsocket/utf8.h src/cwebsocket/common.h src/cwebsocket/common.c src/cwebsocket/utf8.c src/cwebsocket/server.h src/cwebsocket/server.c src/websocket-server.c

AM_CFLAGS= -Wall

if DEBUG
  AM_CFLAGS += -g3
else
  AM_CFLAGS += -O3
endif

clean:
	rm -rf autoscan.log config.h.in config.h config.cache configure install-sh aclocal.m4 autom4te.cache/ config.log config.status Debug/ depcomp .deps/ m4/ Makefile Makefile.in missing stamp-h1 *.o src/*.o *~ websocket-client websocket-server
