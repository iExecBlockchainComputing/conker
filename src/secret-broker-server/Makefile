CC=cc
CFLAGS += -Wall -I/usr/local/include/rats-tls/ 
LDFLAGS += -L/usr/local/lib/rats-tls/

all: secret_broker_server

secret_broker_server: src/secret_broker_server.c
	$(CC) src/secret_broker_server.c -lrats_tls -o $@ $(CFLAGS) $(LDFLAGS)

clean:
	/bin/rm -rf *.o *~ secret_broker_server
