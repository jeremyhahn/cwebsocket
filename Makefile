CFLAGS      = -O3 -g3 -Wall -fmessage-length=0
OBJS        = src/utf8.o src/cwebsocket.o src/main.o
LIBS        = -lcrypto
TARGET      = websocket-client
PLATFORM    = x86_64

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

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
	rm -rf Debug
