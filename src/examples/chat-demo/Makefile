all: risp_chat_server risp_chat_stream risp_chat_send risp_chat_stream2


ARGS=-g -Wall -O2
# -fprofile-arcs -ftest-coverage 
# -pg

DEBUG_LIBS=
#DEBUG_LIBS=-lefence -lpthread

librisp64.so.1.0.0: ../../librisp64/librisp64.so.1.0.0
	cp $^ $@

risp_chat_server: risp_chat_server.c risp_chat_prot.h
	gcc -o $@ risp_chat_server.c $(ARGS) -levent -lrisp64 $(DEBUG_LIBS)

risp_chat_stream: risp_chat_stream.c risp_chat_prot.h
	gcc -o $@ risp_chat_stream.c $(ARGS) -lrisp64 $(DEBUG_LIBS)

risp_chat_stream2: risp_chat_stream2.c risp_chat_prot.h
	gcc -o $@ risp_chat_stream2.c $(ARGS) -lrisp64 $(DEBUG_LIBS)

risp_chat_send: risp_chat_send.c risp_chat_prot.h
	gcc -o $@ risp_chat_send.c $(ARGS) -lrisp64 $(DEBUG_LIBS)


	
	
install: risp_chat_server risp_chat_stream risp_chat_stream2
	@cp risp_chat_server /usr/bin
	@cp risp_chat_stream /usr/bin
	@cp risp_chat_stream2 /usr/bin

clean:
	@-rm risp_chat_server
	@-rm risp_chat_stream
	@-rm risp_chat_stream
	@-rm risp_chat_send

