//--------------------------------------------------------------------------------------------------
// This application will connect to a RISP_CHAT server and will send a chat message to it.

/*
    Copyright (C) 2016  Clinton Webb
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <assert.h>			// assert
#include <arpa/inet.h>		// htons, inet_addr
#include <errno.h>			// errno
#include <fcntl.h>			// fcntl
#include <netdb.h>			// gethostbyname
#include <netinet/in.h>		// inet_addr
#include <signal.h>			// signal
#include <stdio.h>			// printf, fprintf
#include <stdlib.h>			// malloc, atoi, realloc
#include <string.h>			// memcpy
#include <sys/types.h>		// recv, socket, connect, send
#include <sys/socket.h>		// recv, inet_addr, socket, connect, send
#include <unistd.h>			// fcntl, close, getopt

#include <risp.h>
#include <rispstream.h>

#include "risp_chat_prot.h"




typedef struct {
	RISPSTREAM stream;
	RISPSESSION session;
	char *name;
	char *message;
} data_t;


//--------------------------------------------------------------------------------------------------
// this callback is called if we have an invalid command.  We shouldn't be receiving any invalid 
// commands.
void cmdInvalid(void *base, void *data)
{
	unsigned char *cast;
	cast = (unsigned char *) data;
	printf("Received invalid: [%d, %d, %d]\n", cast[0], cast[1], cast[2]);
	assert(0);
}



// does nothing, but it is possible for the server to send it.
void cmdNop(void *base) 
{
}


// server has approved the connection. 
void cmdHelloAck(void *base) 
{
	assert(base);
	data_t *data = base;
	assert(data);
	assert(data->session);
	
	printf("Connected.\n");
	
	// set the session in NO ECHO mode.
	rispsession_send_noparam(data->session, CMD_NOECHO);
	
	// set the session in NO FOLLW mode.
	rispsession_send_noparam(data->session, CMD_NOFOLLOW);

	// set the session in NO UPDATE mode.
	rispsession_send_noparam(data->session, CMD_NOUPDATE);

	// if we have a 'name' specified, then set that.
	if (data->name) {
		rispsession_send_str(data->session, CMD_NAME, strlen(data->name), (risp_data_t *) data->name);
	}
	
	// now add the message
	assert(data->message);
	rispsession_send_str(data->session, CMD_MESSAGE, strlen(data->message), (risp_data_t *) data->message);
		
	// and finally, tell the server to close the connection once it is finished.
	rispsession_send_noparam(data->session, CMD_GOODBYE);
}



//--------------------------------------------------------------------------------------------------
// Callback routine for when a new connection is established as part of the stream.  Locally we 
// would then keep track of the details we need to keep to interact with the stream session.
void connect_cb(RISPSESSION session, void *basedata)
{
	assert(session);
	assert(basedata);
	
	data_t *data = basedata;
	assert(data);
	
	assert(data->session == NULL);
	data->session = session;
	
	fprintf(stderr, "CONNECT CALLBACK.\n");
	
	// Since we are now connected, we need to send the Hello command and the other init commands.

	// to authenticate, we simply must provide the proper HELLO string.  
	unsigned char hello_str[] = "RISP Server";
	rispsession_send_str(session, CMD_HELLO, strlen((char*)hello_str), hello_str);
	
	// By default, the session we create will automatically receive the data of new messages being sent.
	
	// we then wait for some responses.
	
// 	assert(data->stream);
// 	struct event_base *evbase = rispstream_get_eventbase(data->stream);
// 	assert(evbase);
// 	event_base_dump_events(evbase, stderr);
}


//--------------------------------------------------------------------------------------------------
// Callback routine for when a session either fails to connect, or has been closed.
//
// Since we fully expect that we could get a failed connect when first connecting, it is possible 
// that the session is NULL.  However, if the session is closed after the connection is established, 
// we should have a session.   Therefore, if we had a session established, then this should be 
// closing that.  If not, then this sesion is closing, and since it should be the only session we 
// have, the stream processor should exit, and the app should exit.
void close_cb(RISPSESSION session, void *basedata)
{
	data_t *data = basedata;
	assert(data);

	if (session == NULL) {
		assert(data->session == NULL);
		fprintf(stderr, "Unable to connect.\n");
	}
	else {
		assert(data->session == session);
		fprintf(stderr, "Connection closed.\n");
	}
	
// 	assert(data->stream);
// 	struct event_base *evbase = rispstream_get_eventbase(data->stream);
// 	assert(evbase);
// 	event_base_dump_events(evbase, stderr);
}


//--------------------------------------------------------------------------------------------------
// This callback routine is called when process has received an INT signal (normally Ctrl-C by the 
// user).  If we are connected, we need to send a GOODBYE command to the session, and the server 
// should then close it.
void break_cb(RISPSTREAM stream, void *basedata)
{
	data_t *data = basedata;
	assert(data);
	assert(stream);
	
	assert(data->session);
	rispsession_send_noparam(data->session, CMD_GOODBYE);
}

int passphrase_cb(RISPSTREAM stream, int maxlen, char *buffer)
{
	char *buf = getpass("Enter Passphrase: ");
	strncpy(buffer, buf, maxlen);
	return(strlen(buffer));
}


int main(int argc, char **argv)
{
	// parameters that are provided.
	char *srv = "127.0.0.1";
	int port = DEFAULT_PORT;
	char *certfile = NULL;
	char *keyfile = NULL;
	data_t data;

	data.stream = NULL;
	data.session = NULL;
	data.name = NULL;
	data.message = NULL;
	
	int c;
	while ((c = getopt(argc, argv, 
		"s:" /* server hostname or ip */
		"p:" /* port to connect to */
		"c:" /* Certificate Chain */
		"k:" /* Private Key file */
		"n:" /* name of the message sender */
		"m:" /* message to send */
		"h"  /* command usage */
	)) != -1) {
		switch (c) {
			case 'p':
				port = atoi(optarg);
				assert(port > 0);
				break;
			case 's':
				srv = strdup(optarg);	// this will allocate some memory, but we will not be clearing it. When the application exits, it will clear by default.
				assert(srv);
				break;
			case 'c':
				assert(certfile == NULL);
				certfile = optarg;
				assert(certfile);
				break;
			case 'k':
				assert(keyfile == NULL);
				keyfile = optarg;
				assert(keyfile);
				break;
			case 'n':
				data.name = strdup(optarg);
				assert(data.name);
				break;
			case 'm':
				data.message = strdup(optarg);
				assert(data.message);
				break;
			case 'h':
				printf("Usage: ./risp_chat_send -s [server] -p [port] -n \"name of sender\" -m \"Message\"\n\n");
				exit(1);
				break;
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
		}
	}

	// get an initialised risp structure.
	RISP risp = risp_init();
	assert(risp);

	// add the callback routines for the commands we are going to receive.
	risp_add_command(risp, CMD_NOP,              cmdNop);
	risp_add_command(risp, CMD_HELLO_ACK,        cmdHelloAck);

	risp_add_invalid(risp, &cmdInvalid);

	data.stream = rispstream_init(NULL);
	assert(data.stream);
	struct event_base *evbase = rispstream_get_eventbase(data.stream);
	assert(evbase);

// 	fprintf(stderr, "Stream created\n");
// 	event_base_dump_events(evbase, stderr);

	
	rispstream_attach_risp(data.stream, risp);

// 	fprintf(stderr, "RISP attached.\n");
// 	event_base_dump_events(evbase, stderr);

	
	// The stream can use the event system to trap signals, so we will use that.
	rispstream_break_on_signal(data.stream, SIGINT, break_cb);

// 	fprintf(stderr, "Signal Break added.\n");
// 	event_base_dump_events(evbase, stderr);

	
	// if the keys are encrypted, they will need the passphrase.  Ask the user for this password.
	rispstream_set_passphrase_callback(data.stream, passphrase_cb);
	
	// if the user has specified to use certificates, then they needed to be loaded into the 
	// rispstream instance.  Once certificates are applied, all client connections must also
	// be secure.
	if (certfile && keyfile) {
		fprintf(stderr, "Loading Certificate and Private Keys\n");
		int result = rispstream_add_client_certs(data.stream, certfile, keyfile);
		if (result != 0) {
			fprintf(stderr, "Unable to load Certificate and Private Key files.\n");
			exit(1);
		}
		assert(result == 0);
		printf("Certificate files loaded.\n");
	}

	
// 	event_base_dump_events(evbase, stderr);
	
	// Initiate a connection.  Note that it will only QUEUE the request, and will not actually attempt 
	// the connection until the stream is being processed (rispstream_process).
	assert(srv);
	assert(port > 0);
	rispstream_connect(data.stream, srv, port, &data, connect_cb, close_cb);

// 	event_base_dump_events(evbase, stderr);
	
	// this function will process the stream (assuming the connection succeeds).  
	// When there are no more events, it will exit.
	// When the socket closes, this function should exit.
	rispstream_process(data.stream);

// 	event_base_dump_events(evbase, stderr);
	
	fprintf(stderr, "FINISHED.  SHUTTING DOWN\n");
	
	// Not really needed, but good to do it out of habbit before actually cleaning up the risp object itself.
	rispstream_detach_risp(data.stream);
	
	// since the connect has completed, it either failed to do anything, or it connected, processing completed, 
	// and the socket was closed.  So now we shutdown the stream.
	rispstream_shutdown(data.stream);

	// clean up the risp structure.
	risp_shutdown(risp);
	risp = NULL;
	
	return 0;
}


