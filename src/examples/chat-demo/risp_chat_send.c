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

#include <risp64.h>

#include "risp_chat_prot.h"


// this variable is used to indicate that the user wants this application to exit.  They have 
// pressed Ctrl-C, and we need to drop the connection and exit.
static int _sigtrap = 0;


typedef struct {
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
	
	printf("Connected.\n");
}



void cmdMsgID(void *base, risp_int_t value) 
{
	data_t *data = (data_t *) base;
	assert(data);
	
	assert(value > 0);
	data->msg_id = value;
}



void cmdLatestMsgID(void *base, risp_int_t value) 
{
	data_t *data = (data_t *) base;
	assert(data);
	
	assert(value > 0);
	assert(value >= data->latest_msg_id);
	data->latest_msg_id = value;
}


// store the name provided.  No other action.
void cmdName(void *base, char *value, risp_length_t length)
{
	data_t *data = (data_t *) base;
	assert(data);

	// we either have data, or we dont.
	assert((value && length > 0) || (value == NULL && length == 0));
	
	// if there is already a name stored, then we free it.   
	// NOTE: this is simple to implement, but not very good for large server applications. You will 
	//       end up with memory fragmentation.  For this simple example it is adequate, but use your 
	//       memory more wisely for production applications.  You can implement a buffer that 
	//       expands, or pre-allocate space for the largest name.
	if (data->name) { free(data->name); }
	data->name = malloc(length + 1);
	memcpy(data->name, value, length);
	data->name[length] = 0;
}

// We have received a new message.  For this simple purpose, we are just going to output what we 
// receive.  For proper applications you would do some sanity checking of the data to ensure that it 
// is safe to output.
void cmdMessage(void *base, char *value, risp_length_t length)
{
	data_t *data = (data_t *) base;
	assert(data);

	// we either have data, or we dont.
	assert((value && length > 0) || (value == NULL && length == 0));

	// copy the data to a temporary buffer, and NULL terminate it so it is a string we can use.
	char *message = malloc(length+1);
	assert(message);
	memcpy(message, value, length);
	message[length] = 0;
		
	// Normally you would verify that the data is safe to print, but for this excersize, we are just 
	// going to print it.
	char *name = data->name ? data->name : "Anonymous";
	printf("%s:\n%s\n\n", name, message);

}




//--------------------------------------------------------------------------------------------------
// set the socket in non-blocking mode.  In blocking mode, if it cant perform the operation because 
// either there is no data, or buffers are full, the function will wait until either there is data, 
// or the buffers are free.   In non-blocking mode, if the function cant perform the operation, it 
// will return immediatly with an error code that indicates such.  This allows us to attempt a 
// receive on the socket, but continue and do other things if there is no data ready.
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
		if(hp) {
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

	return(handle);
}


// send over the socket.  Whether we are in blocking mode or not, we will continue sending until all 
// the data is sent.  
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
		if (result <= 0) {
			close(sock);
			sending = 0;
			return(-1);
		}
		else {
			// increase our counter of how much has been sent.  If we have sent everything, then we 
			// will break out of the loop.
			sending -= result;
		}
		assert(sending >= 0);
	}

	return(0);
}





//--------------------------------------------------------------------------------------------------
// Handle the signal.  Any signal we receive can only mean that we need to exit.
void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    _sigtrap ++;
}


int main(int argc, char **argv)
{
	// parameters that are provided.
	char *srv = "127.0.0.1";
	int port = DEFAULT_PORT;
	char *name = NULL;
	char *message = NULL;

	int c;
	while ((c = getopt(argc, argv, 
		"s:" /* server hostname or ip */
		"p:" /* port to connect to */
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
			case 'n':
				name = strdup(optarg);
				assert(name);
				break;
			case 'm':
				message = strdup(optarg);
				assert(message);
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

	// set the signal trap.
	signal(SIGINT, sig_handler);
	
	// connect to the remote socket, and set it to non-blocking.
	assert(srv && port > 0);
	int handle = sock_connect(srv, port);
	if (handle <= 0) {
		printf("Unable to connect to %s:%d\n", srv, port);
	}
	else {

// 		printf("Connected to server.\n");
		
		// to simplify this process, we will join all the commands together.  We will not wait for responses.

		int len = 0;	// this var will have the length of each addition to the buffer.
		int buflen = 0;
		assert(message);
		int bufmax = 1024 + strlen(message);
		if (name) { bufmax += strlen(name); }
		char *buffer = malloc(bufmax);
		assert(buffer);
	
		// to authenticate, we simply must provide the proper HELLO string.  
		char hello_str[] = "RISP Server";
		len = risp_addbuf_str(buffer, CMD_HELLO, strlen(hello_str), hello_str);
		assert(len > 0);
		buflen += len;
		assert(buflen <= bufmax);

		// set the session in NO ECHO mode.
		len = risp_addbuf_noparam(buffer+buflen, CMD_NOECHO);
		assert(len > 0);
		buflen += len;
		assert(buflen <= bufmax);

		// set the session in NO FOLLW mode.
		len = risp_addbuf_noparam(buffer+buflen, CMD_NOFOLLOW);
		assert(len > 0);
		buflen += len;
		assert(buflen <= bufmax);

		// set the session in NO UPDATE mode.
		len = risp_addbuf_noparam(buffer+buflen, CMD_NOUPDATE);
		assert(len > 0);
		buflen += len;
		assert(buflen <= bufmax);

		// if we have a 'name' specified, then set that.
		if (name) {
			len = risp_addbuf_str(buffer+buflen, CMD_NAME, strlen(name), name);
			assert(len > 0);
			buflen += len;
			assert(buflen <= bufmax);
		}
	
		// now add the message
		assert(message);
		len = risp_addbuf_str(buffer+buflen, CMD_MESSAGE, strlen(message), message);
		assert(len > 0);
		buflen += len;
		assert(buflen <= bufmax);
		
		// and finally, tell the server to close the connection once it is finished.
		len = risp_addbuf_noparam(buffer+buflen, CMD_GOODBYE);
		assert(len > 0);
		buflen += len;
		assert(buflen <= bufmax);
		
// 		printf("Sending %d bytes to server.\n", buflen);
		
		// now that the we have the RISP stream created for the command, we need to send it.
		if (sock_send(handle, buffer, buflen) != 0) {
			// couldn't send the command, close the handle, and exit.
			close(handle);
			handle = -1;
		}
		else {

			// now we simply process the socket until it closes.  We dont actually care about processing the data received.
			while (recv(handle, buffer, bufmax, 0) != 0) {
// 				printf("Waiting...\n");
			}
		
			close(handle);
		}
	}

	
	return 0;
}


