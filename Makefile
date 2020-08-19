CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
LDFLAGS = -pthread -lpthread
CFLAGS += $(shell pkg-config --cflags libnm)
LDFLAGS += $(shell pkg-config --libs libnm)

ALL: wifi-monitor client

wifi-monitor: daemon.o server.o
	$(CC) -o $@ server.o daemon.o $(LDFLAGS)

daemon.o: src/daemon.c
	$(CC) $(CFLAGS) -c src/daemon.c

server.o: src/server.c
	$(CC) $(CFLAGS) -c src/server.c

client: client.o
	$(CC) -o $@ client.o $(LDFLAGS)

client.o: src/client.c
	$(CC) $(CFLAGS) -c src/client.c


clean:
	rm -rf *.o wifi-monitor client
