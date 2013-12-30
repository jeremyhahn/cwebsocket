CFLAGS = -O2 -g -Wall -fmessage-length=0

OBJS =	 src/client.o src/main.o

LIBS =

TARGET = websocket-client

$(TARGET):	$(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIBS)

all:	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
