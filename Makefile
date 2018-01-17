OBJS=tmp/router.o tmp/ip2mac.o tmp/senddata.o
LIB_OBJS=tmp/log.o tmp/daemon.o tmp/socket.o tmp/util.o tmp/packet.o

CFLAGS=-g -Wall -I./netlib/ -I./src/
LDLIBS=-lpthread
TARGET=router

$(TARGET): $(LIB_OBJS) $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(LIB_OBJS) $(OBJS) $(LDLIBS)

tmp/router.o: ./src/router.c
	$(CC) $(CFLAGS) -o tmp/router.o -c ./src/router.c

tmp/ip2mac.o: ./src/ip2mac.c
	$(CC) $(CFLAGS) -o tmp/ip2mac.o -c ./src/ip2mac.c

tmp/senddata.o: ./src/senddata.c
	$(CC) $(CFLAGS) -o tmp/senddata.o -c ./src/senddata.c

tmp/log.o: ./netlib/log.c
	mkdir -p tmp/
	$(CC) $(CFLAGS) -o tmp/log.o -c ./netlib/log.c

tmp/daemon.o: ./netlib/daemon.c
	$(CC) $(CFLAGS) -o tmp/daemon.o -c ./netlib/daemon.c

tmp/socket.o: ./netlib/socket.c
	$(CC) $(CFLAGS) -o tmp/socket.o -c ./netlib/socket.c

tmp/util.o: ./netlib/util.c
	$(CC) $(CFLAGS) -o tmp/util.o -c ./netlib/util.c

tmp/packet.o: ./netlib/packet.c
	$(CC) $(CFLAGS) -o tmp/packet.o -c ./netlib/packet.c

clean:
	-rm -f router
	-rm -rf ./tmp/
	-rm -f router.log
