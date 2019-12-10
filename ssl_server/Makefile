all: ssl_server

ssl_server: ssl_server.o
	gcc -o ssl_server ssl_server.o -lpthread -L/usr/lib -lssl -lcrypto

ssl_server.o: ssl_server.c
	gcc -c -o ssl_server.o ssl_server.c

clean:
	rm -f ssl_server *.o