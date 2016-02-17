all: risp_chat_server

ARGS=-g -Wall -O2
# -fprofile-arcs -ftest-coverage 
# -pg

DEBUG_LIBS=
#DEBUG_LIBS=-lefence -lpthread

LIBS=-levent -lrisp64 $(DEBUG_LIBS)

risp_chat_server: risp_chat_server.c
	gcc -o $@ risp_chat_server.c $(ARGS) $(LIBS) 


install: risp_chat_server
	@cp risp_chat_server /usr/bin

clean:
	@-rm risp_chat_server

