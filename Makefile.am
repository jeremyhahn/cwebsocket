AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

COMMON = src/cwebsocket/utf8.h src/cwebsocket/utf8.c src/cwebsocket/common.h src/cwebsocket/common.c
ECHO_CLIENT = src/cwebsocket/subprotocol/echo/echo_client.h src/cwebsocket/subprotocol/echo/echo_client.c
ECHO_SERVER = src/cwebsocket/subprotocol/echo/echo_server.h src/cwebsocket/subprotocol/echo/echo_server.c
WEBSOCKET_CLIENT = src/cwebsocket/client.h src/cwebsocket/client.c
WEBSOCKET_SERVER = src/cwebsocket/server.h src/cwebsocket/server.c

bin_PROGRAMS = websocket-client websocket-server websocket-testsuite
websocket_client_SOURCES = $(ECHO_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT) src/websocket-client.c
websocket_server_SOURCES = $(ECHO_SERVER) $(COMMON) $(WEBSOCKET_SERVER) src/websocket-server.c
websocket_testsuite_SOURCES = $(COMMON) $(WEBSOCKET_CLIENT) src/websocket-testsuite.c

noinst_LIBRARIES = libwsclient.a libwsserver.a
libwsclient_a_SOURCES = $(ECHO_CLIENT) $(COMMON) $(WEBSOCKET_CLIENT)
libwsserver_a_SOURCES = $(ECHO_SERVER) $(COMMON) $(WEBSOCKET_SERVER)

AM_CFLAGS = -Wall
AM_LDFLAGS = 

if DEBUG
AM_CFLAGS += -g3
else
AM_CFLAGS += -O3
endif

so:
	gcc -shared -fPIC $(ECHO_CLIENT) $(WEBSOCKET_CLIENT) -o libwsclient.so
	gcc -shared -fPIC $(ECHO_SERVER) $(WEBSOCKET_SERVER) -o libwsserver.so

clean:
	rm -rf ltmain.sh libtool config.sub config.guess libwsclient.* libwsserver.* .gitignore vgcore.* autoscan.log config.h.in config.h config.cache configure install-sh aclocal.m4 autom4te.cache/ config.log config.status Debug/ depcomp .deps/ m4/ Makefile Makefile.in missing stamp-h1 *.o src/*.o *~ websocket-client websocket-server websocket-testsuite
