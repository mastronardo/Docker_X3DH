# Makefile for Alice and Bob
CC = gcc
CFLAGS = -Wall -I/usr/include -I/usr/local/include -I/app/lib/libxeddsa/include -I/app/lib/libxeddsa/ref10/include
LDFLAGS = -L/usr/lib -L/usr/local/lib
LDLIBS = -lsodium -lxeddsa -lcurl -ljansson

# --- Targets ---
all: alice bob

# Build Alice's client
alice: alice.o common.o http_client.o
	$(CC) $(CFLAGS) -o alice alice.o common.o http_client.o $(LDFLAGS) $(LDLIBS)

# Build Bob's client
bob: bob.o common.o http_client.o
	$(CC) $(CFLAGS) -o bob bob.o common.o http_client.o $(LDFLAGS) $(LDLIBS)

# --- Object Files ---
alice.o: alice.c common.h http_client.h
	$(CC) $(CFLAGS) -c alice.c -o alice.o $(LDFLAGS)

bob.o: bob.c common.h http_client.h
	$(CC) $(CFLAGS) -c bob.c -o bob.o $(LDFLAGS)

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c -o common.o $(LDFLAGS)

http_client.o: http_client.c http_client.h
	$(CC) $(CFLAGS) -c http_client.c -o http_client.o $(LDFLAGS)

# --- Cleanup ---
clean:
	rm -f alice bob *.o