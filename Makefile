CFLAGS = -O3 -g -Wall -fmessage-length=0 -I src/

OBJS =	 src/cwebsocket.o src/main.o

LIBS =

TARGET = websocket-client

$(TARGET):	$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIBS)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
