all: risp_chat_server risp_chat_stream risp_chat_send

ARGS=-g -Wall -O2
# -fprofile-arcs -ftest-coverage 
# -pg

DEBUG_LIBS=
#DEBUG_LIBS=-lefence -lpthread

risp_chat_server: risp_chat_server.c
	gcc -o $@ risp_chat_server.c $(ARGS) -levent -lrisp64 $(DEBUG_LIBS)

risp_chat_stream: risp_chat_stream.c
	gcc -o $@ risp_chat_stream.c $(ARGS) -lrisp64 $(DEBUG_LIBS)

risp_chat_send: risp_chat_send.c
	gcc -o $@ risp_chat_send.c $(ARGS) -lrisp64 $(DEBUG_LIBS)

install: risp_chat_server risp_chat_stream
	@cp risp_chat_server /usr/bin
	@cp risp_chat_stream /usr/bin

clean:
	@-rm risp_chat_server
	@-rm risp_chat_stream
	@-rm risp_chat_send

