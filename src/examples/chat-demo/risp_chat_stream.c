//--------------------------------------------------------------------------------------------------
// This application will connect to a RISP_CHAT server and will stream new messages that are 
// received.
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
// #include <arpa/inet.h>		// htons, inet_addr
#include <errno.h>			// errno
// #include <fcntl.h>			// fcntl
// #include <netdb.h>			// gethostbyname
// #include <netinet/in.h>		// inet_addr
#include <signal.h>			// signal
#include <stdio.h>			// printf, fprintf
#include <stdlib.h>			// malloc, atoi, realloc
#include <string.h>			// memcpy, strndup
// #include <sys/types.h>		// recv, socket, connect, send
// #include <sys/socket.h>		// recv, inet_addr, socket, connect, send
#include <unistd.h>			// fcntl, getopt

#include <rispstream.h>

#include "risp_chat_prot.h"



// The data that is used by the stream session.  
// Note that this code is assuming that it has one connection to the server and therefore doesn't keep seperate data sets for more than one session.  Since we only have one session, we just keep it all in one place.
typedef struct {
	RISPSTREAM *stream;
	RISPSESSION *session;
	
	risp_int_t msg_id;
	risp_int_t latest_msg_id;
	char *name;
	
} data_t;



// does nothing, but it is possible for the server to send it.
void cmdNop(void *basedata) 
{
}


// server has approved the connection. 
void cmdHelloAck(void *base) 
{
	assert(base);
	
	fprintf(stderr, "Connected.\n");
}



void cmdMsgID(void *base, risp_int_t value) 
{
	data_t *data = (data_t *) base;
	assert(data);
	
	assert(value > 0);
	data->msg_id = value;

	if (value > data->latest_msg_id) {
		data->latest_msg_id = value;
	}
	
// 	printf("CMD_MSG_ID: %ld\n", value);	
}



void cmdLatestMsgID(void *base, risp_int_t value) 
{
	data_t *data = (data_t *) base;
	assert(data);
	
	assert(value >= 0);
	assert(value >= data->latest_msg_id);
	data->latest_msg_id = value;
	
// 	printf("CMD_LATEST_MSG_ID: %ld\n", value);	
}


// store the name provided.  No other action.
void cmdName(void *base, risp_length_t length, char *value)
{
	data_t *data = (data_t *) base;
	assert(data);

// 	printf("CMD_NAME: length:%d\n", length);

	
	// we either have data, or we dont.
	assert((value && length > 0) || (value == NULL && length == 0));
	
	// if there is already a name stored, then we free it.   
	// NOTE: this is simple to implement, but not very good for large server applications. You will 
	//       end up with memory fragmentation.  For this simple example it is adequate, but use your 
	//       memory more wisely for production applications.  You can implement a buffer that 
	//       expands, or pre-allocate space for the largest name.
	if (data->name) { free(data->name); }
	data->name = malloc(length + 1);
	assert(data->name);
	memcpy(data->name, value, length);
	data->name[length] = 0;
	
// 	printf("CMD_NAME: '%s'\n", data->name);
}

// We have received a new message.  For this simple purpose, we are just going to output what we 
// receive.  For proper applications you would do some sanity checking of the data to ensure that it 
// is safe to output.
void cmdMessage(void *base, risp_length_t length, char *value)
{
	data_t *data = (data_t *) base;
	assert(data);

// 	printf("CMD_MESSAGE len:%ld\n", length);
	
	// we either have data, or we dont.
	assert((value && length > 0) || (value == NULL && length == 0));

	// copy the data to a temporary buffer, making sure it is null-terminated. 
	
	char *message = malloc(length+1);
	memcpy(message, value, length);
	assert(message);
	message[length] = 0;
		
	// Normally you would verify that the data is safe to print, but for this excersize, we are just 
	// going to print it.
	char *name = data->name ? data->name : "Anonymous";
	printf("%s: %s\n", name, message);

}







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
	
// 	fprintf(stderr, "CONNECT CALLBACK.\n");
	
	// Since we are now connected, we need to send the Hello command and the other init commands.

	// to authenticate, we simply must provide the proper HELLO string.  
	unsigned char hello_str[] = "RISP Server";
	rispsession_send_str(session, CMD_HELLO, strlen((char*)hello_str), hello_str);
	
	// By default, the session we create will automatically receive the data of new messages being sent.
	
	// we then wait for some responses.
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
	
	assert((data->session == NULL && session == NULL) || (data->session == session));
	
	// nothing else to do.
	if (session == NULL) {
		fprintf(stderr, "Unable to connect.\n");
	}
	else {
		fprintf(stderr, "Connection closed.\n");
	}
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
	char *cafile = NULL;
	char *keyfile = NULL;
	int force_enc = 0;

	// this data object will be passed to all the callback routines.  Initialise it.
	data_t data;
	data.session = NULL;
	data.stream = NULL;
	data.msg_id = 0;
	data.latest_msg_id = 0;
	data.name = NULL;

	// get the command line options.
	int c;
	while (-1 != (c = getopt(argc, argv, 
			"p:" /* port */
			"s:" /* Server host */
			"e"  /* use encryption for the connection. */
			"c:" /* Certificate Chain */
			"k:" /* Private Key file */
			"h"  /* help */ 
		))) {
		switch (c) {
			case 'p':
				port = atoi(optarg);
				assert(port > 0);
				break;
			case 's':
				srv = strdup(optarg);
				assert(srv != NULL);
				break;				
			case 'c':
				assert(cafile == NULL);
				cafile = optarg;
				assert(cafile);
				break;
			case 'k':
				assert(keyfile == NULL);
				keyfile = optarg;
				assert(keyfile);
				break;
			case 'e':
				force_enc =  1;
				break;
			case 'h':
			default:
				printf("usage:\n\nrisp_chat_stream [-s server] [-p port] [-e] [-c cafile] [-k keyfile] [-h]\n");
				exit(1);
				break;
		}
	}

	// get an initialised risp structure.
	RISP risp = risp_init();
	assert(risp);

	// add the callback routines for the commands we are going to receive.
	risp_add_command(risp, CMD_NOP,              cmdNop);
	risp_add_command(risp, CMD_HELLO_ACK,        cmdHelloAck);
	risp_add_command(risp, CMD_MSG_ID,           cmdMsgID);
	risp_add_command(risp, CMD_LATEST_MSG_ID,    cmdLatestMsgID);
	risp_add_command(risp, CMD_NAME,             cmdName);
	risp_add_command(risp, CMD_MESSAGE,          cmdMessage);

	risp_add_invalid(risp, &cmdInvalid);

	data.stream = rispstream_init(NULL);
	assert(data.stream);

	rispstream_attach_risp(data.stream, risp);
	
	// The stream can use the event system to trap signals, so we will use that.
	rispstream_break_on_signal(data.stream, SIGINT, break_cb);
	
	// if we are using encryption, pass the details on to rispstream.  Note that this setting 
	// is used to connect using SSL, but doesn't necessarily imply that client-certs are required.
	if (force_enc > 0) {
		rispstream_use_ssl(data.stream);
	}

	// if the keys are encrypted, they will need the passphrase.  Ask the user for this password.
	rispstream_set_passphrase_callback(data.stream, passphrase_cb);
	
	// if the user has specified to use certificates, then they needed to be loaded into the 
	// rispstream instance.  Once certificates are applied, all client connections must also
	// be secure.
	if (cafile && keyfile) {
		fprintf(stderr, "Loading Certificate and Private Keys\n");
		int result = rispstream_add_client_certs(data.stream, cafile, keyfile);
		if (result != 0) {
			fprintf(stderr, "Unable to load Certificate and Private Key files.\n");
			exit(1);
		}
		assert(result == 0);
		printf("Certificate files loaded.\n");
	}
	
	// Initiate a connection.  Note that it will only QUEUE the request, and will not actually attempt 
	// the connection until the stream is being processed (rispstream_process).
	assert(srv);
	assert(port > 0);
	rispstream_connect(data.stream, srv, port, &data, connect_cb, close_cb);

	// this function will process the stream (assuming the connection succeeds).  
	// When there are no more events, it will exit.
	// When the socket closes, this function should exit.
	rispstream_process(data.stream);

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


