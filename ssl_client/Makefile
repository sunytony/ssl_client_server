all: ssl_client

ssl_client: ssl_client.o
	gcc -o ssl_client ssl_client.o -lpthread -L/usr/lib -lssl -lcrypto

ssl_client.o: ssl_client.c
	gcc -c -o ssl_client.o ssl_client.c

clean:
	rm -f ssl_client *.o