CFLAGS = -O3 -g3 -Wall -fmessage-length=0

OBJS =	 src/base64.o src/cwebsocket.o src/main.o

LIBS = -lcrypto

TARGET = websocket-client

$(TARGET):	$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIBS)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
