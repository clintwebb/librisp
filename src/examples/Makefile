all: risp_local risp_server risp_client

ARGS=-Wall -O2

risp_local: risp_local.c
	gcc -o $@ risp_local.c -l risp $(ARGS)

risp_server: risp_server.c daemon.c daemon.h
	gcc -o $@ risp_server.c daemon.c -l risp -l event $(ARGS)

risp_client: risp_client.c
	gcc -o $@ risp_client.c -l risp $(ARGS)

clean:
	@-test -e risp_local && rm risp_local
	@-test -e risp_client && rm risp_client
	@-test -e risp_server && rm risp_server