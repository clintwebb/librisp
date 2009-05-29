all: risp_local risp_server risp_client struct_server struct_client

ARGS=-Wall -O2

risp_local: risp_local.c
	gcc -o $@ risp_local.c -lrisp $(ARGS)

risp_server: risp_server.c daemon.c daemon.h
	gcc -o $@ risp_server.c daemon.c -lrisp -levent $(ARGS)

risp_client: risp_client.c
	gcc -o $@ risp_client.c -lrisp $(ARGS)

struct_server: struct_server.c daemon.c daemon.h
	gcc -o $@ struct_server.c daemon.c -levent $(ARGS)

struct_client: struct_client.c
	gcc -o $@ struct_client.c $(ARGS)

clean:
	@-test -e risp_local && rm risp_local
	@-test -e risp_client && rm risp_client
	@-test -e risp_server && rm risp_server
	@-test -e struct_server && rm struct_server
	@-test -e struct_client && rm struct_client
