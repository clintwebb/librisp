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



/*
 * This version of the streaming app, handles the incoming messages differrently, to show different 
 * aspects of the protocol.  The first streaming app is set in FOLLOW mode, where it receives full 
 * messages as they are sent.  This version will be in NO_FOLLOW mode where it only receives the new 
 * latest ID, and then it asks for the list of messages since the last ID it processed.   
 * 
 * This allows it to also catch up and display the chats that occurred before the connection was made. 
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
#include <string.h>			// memcpy, strndup
#include <sys/types.h>		// recv, socket, connect, send
#include <sys/socket.h>		// recv, inet_addr, socket, connect, send
#include <unistd.h>			// fcntl, close, getopt

#include <risp64.h>

#include "risp_chat_prot.h"



#define CHUNK_SIZE 4096
// #define CHUNK_SIZE 8

// this variable is used to indicate that the user wants this application to exit.  They have 
// pressed Ctrl-C, and we need to drop the connection and exit.
static int _sigtrap = 0;


typedef struct {
	int handle;
	risp_int_t msg_id;
	risp_int_t latest_msg_id;
	char *name;
} data_t;



// does nothing, but it is possible for the server to send it.
void cmdNop(void *base) 
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
	
// 	printf("CMD_MSG_ID: %d\n", value);	
}

// send over the socket.  Return 0 if socket is still connected, -1 if the socket has closed.
int sock_send(int sock, char *data, int len)
{
	assert(sock >= 0);
	assert(data);
	assert(len > 0);
	
	int sending = len;
	while (sending > 0) {
		// send what data we have left to send.
		int result = send(sock, data+(len-sending), sending, 0);
	
		// TODO: Should check for blocking mode, as it may have been set.
		// we are in blocking mode, so if we received a 0 or less, then the socket is closed.
		if (result == 0) {
			close(sock);
			sending = 0;
			return(-1);
		}
		else if (result > 0) {
			// increase our counter of how much has been sent.  If we have sent everything, then we 
			// will break out of the loop.
			sending -= result;
		}
		assert(sending >= 0);
	}

	return(0);
}


// attempt to send a request, return zero if successful.  
// If the send fails, then close the socket and return a non-zero..
int sendMessageRequest(int handle, risp_int_t msg_id)
{
	assert(msg_id > 0);
	assert(handle >= 0);
	
	// the command will be generated and placed in a buffer.  1024 bytes is PLENTY for this 
	// command... 
	char buffer[1024];
	
	risp_length_t len = risp_addbuf_int(buffer, CMD_SEND_MSG, msg_id);
	assert(len > 0);
	
	// now that the we have the RISP stream created for the command, we need to send it.
	return(sock_send(handle, buffer, len));
}

// If the LatestMsgID is greater than our current stored value, then we need to request the messages that we are missing.
void cmdLatestMsgID(void *base, risp_int_t value) 
{
	data_t *data = (data_t *) base;
	assert(data);
	
	assert(value >= 0);
	assert(value >= data->latest_msg_id);

	while (data->latest_msg_id < value && data->handle >= 0) {
		data->latest_msg_id ++;
		assert(value >= data->latest_msg_id);
		
		if(sendMessageRequest(data->handle, data->latest_msg_id) != 0) {
			// the send failed, so we need to mark the socket as unused. 
			data->handle = -1;
		}
	}
	
	assert(data->latest_msg_id == value);
	
 	printf("CMD_LATEST_MSG_ID: %ld\n", value);	
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
// set the socket in non-blocking mode.  In blocking mode, if it cant perform the operation because 
// either there is no data, or buffers are full, the function will wait until either there is data, 
// or the buffers are free.   In non-blocking mode, if the function cant perform the operation, it 
// will return immediatly with an error code that indicates such.  This allows us to attempt a 
// receive on the socket, but continue and do other things if there is no data ready.
// 
// NOTE: We are not using this function in this application, but providing it here in the example, 
//       because it is something you likely will need to use in your own similar applications.
void sock_nonblock(int handle)
{
	assert(handle > 0);
	
	int opts = fcntl(handle, F_GETFL);
	if (opts >= 0) {
		opts = (opts | O_NONBLOCK);
		fcntl(handle, F_SETFL, opts);
	}
}

//--------------------------------------------------------------------------------------------------
// connect to the host and port.  
// Return the socket handle on success.  
// Otherwise return negative value.
int sock_connect(char *host, int port)
{
	int handle = -1;
	int resolved = 0;

	struct sockaddr_in sin;
	assert(host && port > 0);
	
    assert(host && host[0] != '\0' && port > 0);

    // First, assign the family (IPv4 and port).
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    // Look up by standard notation (xxx.xxx.xxx.xxx) first.
    unsigned long ip4addr = inet_addr(host);
    if ( ip4addr != (unsigned long)(-1) )  {
        // Success. Assign, and we're done.  Since it was an actual IP address, then we dont do any 
        // DNS lookup for that, so we cant do any checking for any other address type (such as MX).
        sin.sin_addr.s_addr = ip4addr;
		resolved ++;
    }
    else {
		// If that didn't work, try to resolve host name by DNS.
		struct hostent *hp = gethostbyname(host);
		if (hp) {
			memcpy( &(sin.sin_addr.s_addr), &(hp->h_addr[0]), hp->h_length);
			resolved ++;
		}
	}
	
	// if we were able to resolve the server:port, then we continue.
	if (resolved > 0) {
		// Create the socket
		handle = socket(AF_INET,SOCK_STREAM,0);
		if (handle >= 0) {
			// Connect to the server
			if (connect(handle, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0) {
				// was unable to connect, so we close the socket handle.  Set the handle to -1 to 
				// indicate failure.
				close(handle);
				handle = -1;
			}
		}
	}
	else {
		assert(handle < 0);
	}

	return(handle);
}







//--------------------------------------------------------------------------------------------------
// Handle the signal.  Any signal we receive can only mean that we need to exit.
void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    _sigtrap ++;
}


// Send the various Initialisation commands.  These include :
//  - HELLO
//  - NO_FOLLOW
//  - CMD_GET_LATEST_MDG_ID
// Return 0 if the socket is still valid.  Return -1 if the 
// socket closed or there was an error while sending.
int sendInit(int handle)
{
	if (handle < 0) { return -1; }
	
	// the hello command will be generated and placed in a buffer.  1024 bytes is PLENTY for this 
	// command... but just showing that the buffer doesn't need to be the exact size, just as long 
	// as it is big enough.
	char buffer[1024];
	
	// to authenticate, we simply must provide the proper HELLO string.  
	char hello_str[] = "RISP Server";
	
	risp_length_t len = 0;
	len += risp_addbuf_str(    buffer+len, CMD_HELLO, strlen(hello_str), hello_str);
	len += risp_addbuf_noparam(buffer+len, CMD_NOFOLLOW);
	len += risp_addbuf_noparam(buffer+len, CMD_GET_LATEST_MDG_ID);
	
	// now that the we have the RISP stream created for the command, we need to send it.
	return(sock_send(handle, buffer, len));
}






// send the GOODBYE command to the server.  Return 0 if the socket is still valid.  Return -1 if the 
// socket closed or there was an error while sending.
int sendGoodbye(int handle)
{
	// the command will be generated and placed in a buffer.  1024 bytes is PLENTY for this 
	// command... but just showing that the buffer doesn't need to be the exact size, just as long 
	// as it is big enough.
	char buffer[1024];
	
	risp_length_t len = risp_addbuf_noparam(buffer, CMD_GOODBYE);
	assert(len > 0);
	
	// now that the we have the RISP stream created for the command, we need to send it.
	return(sock_send(handle, buffer, len));
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



int main(int argc, char **argv)
{
	// parameters that are provided.
	char *srv = "127.0.0.1";
	int port = DEFAULT_PORT;

	// this data object will be passed to all the callback routines.  Initialise it.
	data_t data;
	data.handle = -1;
	data.msg_id = 0;
	data.latest_msg_id = 0;
	data.name = NULL;

	// get the command line options.
	int c;
	while ((c = getopt(argc, argv, "p:s:h")) != -1) {
		switch (c) {
			case 'p':
				port = atoi(optarg);
				assert(port > 0);
				break;
			case 's':
				srv = strdup(optarg);
				assert(srv != NULL);
				break;				
			case 'h':
				printf("usage:\n\nrisp_chat_stream2 [-s server] [-p port] [-h]\n");
				exit(1);
				break;
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
		}
	}

	// set the signal trap, so we can break out of the loop when user presses Ctrl-C.
	signal(SIGINT, sig_handler);
	
	// get an initialised risp structure.
	risp_t *risp = risp_init(NULL);
	assert(risp);

	// add the callback routines for the commands we are going to receive.
	risp_add_command(risp, CMD_NOP,              &cmdNop);
	risp_add_command(risp, CMD_HELLO_ACK,        &cmdHelloAck);
	risp_add_command(risp, CMD_MSG_ID,           &cmdMsgID);
	risp_add_command(risp, CMD_LATEST_MSG_ID,    &cmdLatestMsgID);
	risp_add_command(risp, CMD_NAME,             &cmdName);
	risp_add_command(risp, CMD_MESSAGE,          &cmdMessage);

	risp_add_invalid(risp, &cmdInvalid);

	
	// connect to the remote socket. We will leave it in blocking mode.  When we do the recv, we 
	// will specify that the recv operation is non-blocking.
	assert(srv && port > 0);
	data.handle = sock_connect(srv, port);
	if (data.handle <= 0) {
		printf("Unable to connect to %s:%d\n", srv, port);
	}
	else {
		// now that we are connected, first we need to send the HELLO and NO_FOLLOW commands.  
		// These commands could have been lumped together in a single send, but for the purpose of 
		// demonstrating RISP, this code does each operationg specifically.
		if (sendInit(data.handle) != 0) {
			// couldn't send the command, close the handle, and exit.
			close(data.handle);
			data.handle = -1;
		}
		
		// setup the initial buffer.  Since we dont really know how much data we will receive from 
		// the server, we will grow the buffer as needed.
		int max = 0;
		char *buffer = NULL;
		int used = 0;
		int goodbye_sent = 0;	// if we have sent a GOODBYE, we dont want to 
		
		// we will loop until the socket is closed.  If the user presses Ctrl-C, we will send a 
		// GOODBYE command to the server, which will then close the socket.  If the user presses 
		// Ctrl-C more than once, we will not wait for the server, and will close the socket 
		// directly.  Every time the user presses Ctrl-C, it should break out of the sleep, so it 
		// should respond pretty quickly.
		while (data.handle >= 0) {
		
// 			printf(".");
			
			assert(used <= max);
			
			if (max-used < CHUNK_SIZE) { 
				max += CHUNK_SIZE;
				buffer = realloc(buffer, max);
				assert(buffer);
// 				fprintf(stderr, "Increased Max Buffer to %d\n", max);
			}
			
			// check for data on the socket.  We will do the receive in non-blocking mode, so if 
			// there is no data, it will return immediately. If we received no data, we will wait for 
			// 1 second before trying again.  If we have waited for 5 seconds, then we need to 
			// send a NOP to keep the connection alive.
			char *ptr = buffer + used;
			int avail = max - used;
// 			fprintf(stderr, "About to recv.  avail=%d\n", avail);
			int result = recv(data.handle, ptr, avail, MSG_DONTWAIT);
// 			printf("Recv: result=%d, used=%d, max=%d\n", result, used, max);
			if (result < 0) {
				assert(result == -1);
				if (errno == EWOULDBLOCK || errno == EAGAIN) {
					// there was no data to read from the socket.
					// we will now sleep for 1 second.  If the user pressed Ctrl-C, then the sleep 
					// function will exit immediately. Only do the sleep if Ctrl-C hasn't been hit.
					if (_sigtrap == 0) { sleep(1); }
				}
				else {
					fprintf(stderr, "Unexpected result received from socket. errno=%d '%s'\n", errno, strerror(errno));
				}
			}
			else if (result == 0) {
				// socket has closed.
				close(data.handle);
				data.handle = -1;
			}
			else {
				assert(result > 0);
				assert(result <= avail);
				assert(used >= 0);
				used += result;
				assert(used <= max);
				
				// if we have some data received, then we need to process it.
// 				fprintf(stderr, "Processing: %d\n", used);
				risp_length_t processed = risp_process(risp, &data, used, buffer);
// 				fprintf(stderr, "Processed: %ld\n", processed);
				assert(processed >= 0);
				assert(processed <= used);
				
				if (processed < used) { 
					// Our commands have probably been fragmented.
					
// 					fprintf(stderr, "Fragmented commands: processed=%ld, used=%d, max=%d\n", processed, used, max);
					fflush(stdout);
					
					if (processed > 0) {
						// we need to remove from the buffer the data that we have processed.  
						// This is a simple approach, but not the most efficient.
						assert(sizeof(*buffer) == 1);
						char *ptr = buffer+processed;
						size_t length = used-processed;
						assert((processed + length) == used);
						
// 						fprintf(stderr, "Moving data.  length=%ld\n", length);
						
						memmove(buffer, ptr, length);
						
						used -= processed;
						assert(used > 0);
						assert(used < max);
						
// 						fprintf(stderr, "After move. used=%d, max=%d\n", used, max);
					}
				} 
				else { used = 0; }
				
				assert(used >= 0 && used <= max);
			}
			
			
			if (data.handle >= 0) {
				if (_sigtrap == 1 && goodbye_sent == 0) {
					fprintf(stderr, "Closing...\n");
					
					// TODO: shouldn't just close the socket.  Should instead send GOODBYE command and wait for socket to close.
					if (sendGoodbye(data.handle) != 0) {
						close(data.handle);
						data.handle = -1;
					}
					
					goodbye_sent ++;
				}
				else if (_sigtrap > 1) {
					close(data.handle);
					data.handle = -1;
				}
			}
		}
	}

	// clean up the risp structure.
	risp = risp_shutdown(risp);
	assert(risp == NULL);
	
	return 0;
}


