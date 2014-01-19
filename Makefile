CFLAGS      = -O3 -g3 -Wall -fmessage-length=0
OBJS        = src/utf8.o src/cwebsocket.o src/main.o
SRC         = src/utf8.c src/cwebsocket.c src/main.c
LIBS        = -lcrypto
TARGET      = websocket-client
TARGET_LIB  = libcwebsocket.so
PLATFORM    = x86_64

.PHONY: lib clean

ifdef NOTHREADS
else
  CFLAGS += -pthread -DTHREADED
  LIBS += -lpthread
endif

ifdef NOSSL
else
   CFLAGS += -DUSESSL
   LIBS += -lssl
endif

ifeq ($(PLATFORM), x86)
	CFLAGS += -m32
endif

ifeq ($(PLATFORM), x86_64)
	CFLAGS += -m64
endif

ifeq ($(PLATFORM), arm)
	CFLAGS += -pipe -mfpu=vfp -mfloat-abi=hard
endif

$(TARGET):	$(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)
	rm -rf src/*.o

all:	$(TARGET)

so:
	rm -f $(OBJS)
	gcc -c -Wall -Werror -fPIC $(SRC) $(LIBS)
	gcc -shared -o $(TARGET_LIB) cwebsocket.o
	rm -f *.o

clean:
	rm -rf $(OBJS) $(TARGET) $(TARGET_LIB) Debug
