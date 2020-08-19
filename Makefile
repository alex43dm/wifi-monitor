CC = gcc
CFLAGS = -g -Wall -Wextra -Iinclude
LDFLAGS = -g -lpthread
CFLAGS += $(shell pkg-config --cflags libnm)
LDFLAGS += $(shell pkg-config --libs libnm)

ALL: wifi-monitor client

wifi-monitor: daemon.o server.o
	$(CC) $(LDFLAGS) -o $@ server.o daemon.o

daemon.o: src/daemon.c
	$(CC) $(CFLAGS) -c src/daemon.c

server.o: src/server.c
	$(CC) $(CFLAGS) -c src/server.c

client: client.o
	$(CC) $(LDFLAGS) -o $@ client.o

client.o: src/client.c
	$(CC) $(CFLAGS) -c src/client.c


clean:
	rm -rf *.o wifi-monitor client
