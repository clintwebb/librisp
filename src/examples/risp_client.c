//-----------------------------------------------------------------------------
// Example of a librisp protocol handler.
//
// With this standalone example, we will be simulating a data stream that would 
// come from a socket.
//
// Normally with a socket based stream, we would have some information about 
// that socket, at the very least, a handle to it.  We would also want to keep 
// a buffer for any data that is incomplete, waiting for more.  
//
// So that this example can mimic the way that you would normally do it with a 
// socket stream, we will keep a node structure that is similar to what you 
// would expect.  


#include <risp.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "risp_server_prot.h"

#define MAX_BUFFER (1024*512)
#define TEST_STR	240
#define TEST_MULT 8

static int sigtrap = 0;


// The node structure.  This should be modified to fit your needs, but there 
// should be one for each socket connection that is being processed.  When 
// processing the data stream, the library is not responsible for data that is 
// incomplete.  It will be up to you to make sure that incomplete data is 
// added to a buffer, and re-processed when new data becomes available.
typedef struct {
	int handle;
	char *buffer;
	int length;
	
	// the variables and flags that represent the data received from commands.
	int status;

} node_t;




// This callback function is to be fired when the CMD_CLEAR command is 
// received.  It should clear off any data received and stored in variables 
// and flags.  In otherwords, after this is executed, the node structure 
// should be in a predictable state.
void cmdClear(void *base) 
{
	// The base pointer that is passed thru the library doesnt know about the 
	// node structure we are using, so we need to make a cast-pointer for it.
	node_t *ptr = (node_t *) base;
	
	// Always a good idea to put lots of asserts in your code.  It helps to 
	// capture developer mistakes that would sometimes be difficult to catch at 
	// a later date.
	assert(ptr != NULL);
	
	// Now we clear off our protocol specific variables and flags.
	ptr->status = 0;
}


// This callback function is called when the CMD_EXECUTE command is received.  
// It should look at the data received so far, and figure out what operation 
// needs to be done on that data.  Since this is a simulation, and our 
// protocol doesn't really do anything useful, we will not really do much in 
// this example.   
void cmdExecute(void *base) 
{
	node_t *ptr = (node_t *) base;
	assert(ptr != NULL);
	
	// All we can do really in this exercise is to print out the values that we have.
//  	printf("Execute!  (url: '%s', ttl: %d)\n", ptr->url, ptr->ttl);
}



void cmdStatus(void *base, risp_int_t value) 
{
	node_t *ptr = (node_t *) base;
	assert(base != NULL);
	assert(value >= 0 && value < 256);
	
	ptr->status = value;
}







int sock_resolve(const char *szAddr, int iPort, struct sockaddr_in *pSin)
{
    unsigned long ulAddress;
    struct hostent *hp;

    assert(szAddr != NULL && szAddr[0] != '\0' && iPort > 0);
    assert(pSin != NULL);

    // First, assign the family and port.
    pSin->sin_family = AF_INET;
    pSin->sin_port = htons(iPort);

    // Look up by standard notation (xxx.xxx.xxx.xxx) first.
    ulAddress = inet_addr(szAddr);
    if ( ulAddress != (unsigned long)(-1) )  {
        // Success. Assign, and we're done.  Since it was an actual IP address, then we dont doany DNS lookup for that, so we cant do any checking for any other address type (such as MX).
        pSin->sin_addr.s_addr = ulAddress;
        return 0;
    }


    // If that didn't work, try to resolve host name by DNS.
    hp = gethostbyname(szAddr);
    if( hp == NULL ) {
        // Didn't work. We can't resolve the address.
        return -1;
    }

    // Otherwise, copy over the converted address and return success.
    memcpy( &(pSin->sin_addr.s_addr), &(hp->h_addr[0]), hp->h_length);
    return 0;
}

void sock_nonblock(int nsock)
{
		int opts;

		assert(nsock>0);
		opts = fcntl(nsock, F_GETFL);
		if (opts >= 0) {
				opts = (opts | O_NONBLOCK);
				fcntl(nsock, F_SETFL, opts);
		}
}


int sock_connect(char *szHost, int nPort)
{
    int nSocket = 0;
    struct sockaddr_in sin;

    assert(szHost != NULL);
    assert(nPort > 0);

    if (sock_resolve(szHost,nPort,&sin) >= 0) {
        // CJW: Create the socket
        nSocket = socket(AF_INET,SOCK_STREAM,0);
        if (nSocket >= 0) {
            // CJW: Connect to the server
            if (connect(nSocket, (struct sockaddr*)&sin, sizeof(struct sockaddr)) >= 0) {
                sock_nonblock(nSocket);   // and set the socket for non-blocking mode.
            }
            else {
                close(nSocket);
                nSocket = 0;
            }
        }
    }
    
    return(nSocket);
}

void sock_close(int nsock)
{
	assert(nsock > 0);
	int result;
	result = close(nsock);
	assert(result == 0);
}


int sock_receive(int nsock, char *data, int len)
{
	ssize_t nResult = -1;

	nResult = recv(nsock, data, len, 0);
	if (nResult == 0) {
		nResult = -1;
	}
	else if (nResult < 0) {
		switch (errno) {
			case EAGAIN:
				nResult = 0;
				break;
		} 
	}

	return(nResult);
}


// send over the socket, continuing to try to send if it is blocking.
int sock_send(int sock, char *data, int len)
{
	int nResult = 0;

	nResult = send(sock, data, len, 0);
	if (nResult == 0) {
		close(sock);
		nResult = -1;
	}
	else if (nResult < 0) {
		// we got an error on the socket, so make a note of the error number.
		switch (errno) {
			case EAGAIN: 
				nResult = 0;
				break;
				
			default:
				close(sock); 
				assert(nResult == -1); 
				break;
		}
	}

	return(nResult);
}










//-----------------------------------------------------------------------------
// Handle the signal.  Any signal we receive can only mean that we need to exit.
void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    sigtrap ++;
}



int main(int argc, char **argv)
{
	int c;
	risp_t *risp;
	char buff[MAX_BUFFER];
	int sent;
	char *srv = "127.0.0.1";
	int port = DEFAULT_PORT;
	int red, blue;
	int partial;
	int max;
	int i;


	node_t node;

	node.handle = 0;
	node.buffer = NULL;
	node.length = 0;


	while ((c = getopt(argc, argv, "p:s:")) != -1) {
		switch (c) {
			case 'p':
				port = atoi(optarg);
				assert(port > 0);
				break;
			case 's':
				srv = optarg;
				assert(srv != NULL);
				break;				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
		}
	}


	// get an initialised risp structure.
	risp = risp_init();
	if (risp == NULL) {
		printf("Unable to initialise RISP library.\n");
	}
	else {
		risp_add_command(risp, CMD_CLEAR, 	&cmdClear);
		risp_add_command(risp, CMD_EXECUTE, &cmdExecute);
		risp_add_command(risp, CMD_STATUS,  &cmdStatus);
		
		// build the operation that we want to send.	
		max = 0;
		buff[max++] = CMD_CLEAR;
		buff[max++] = CMD_URL;
		buff[max++] = (unsigned char) TEST_STR;
		max += TEST_STR;
		buff[max++] = CMD_TTL;
		buff[max++] = (unsigned char) 15;
		buff[max++] = CMD_EXECUTE;
		buff[max++] = CMD_URL;
		buff[max++] = (unsigned char) TEST_STR;
		max += TEST_STR;
		buff[max++] = CMD_TTL;
		buff[max++] = (unsigned char) 30;
		buff[max++] = CMD_EXECUTE;
		
		for( i=0; i<TEST_MULT; i++) {
			assert((max * 2) <= MAX_BUFFER);
			memmove(&buff[max], buff, max);
			max = max + max;
		}
		
		assert(max <= MAX_BUFFER);
		
		// and process it a lot of time.
		printf("Sending data stream.\n");
		
		// connect to the remote socket.
		node.handle = sock_connect(srv, port);
		if (node.handle <= 0) {
			printf("Unable to connect to %s:%d\n", srv, port);
		}
		else {
			red = 100;
			blue = 0;
			partial = 0;
			while (sigtrap == 0) {
			
				// continue to send data to the socket over and over as quickly as possible.
				sent = sock_send(node.handle, buff+partial, max-partial);
				if (sent < 0) { sigtrap ++; }
				else if (sent == 0) {
					putchar('@');
					usleep(15);
				}
				else {
					assert(sent <= max);
					if (sent < (max-partial)) {
						usleep(5);
						partial += sent;
						assert(partial < max);
						putchar('#');
					}
					else {
						partial = 0;
					}
					
					red --;
					if (red == 0) {
						putchar('.');
						red = 100;
						blue++;
						if (blue == 80) {
							putchar('\n');
							blue = 0;
						}
					}
				}	
					
			}
			
			// close the socket.
			if (node.handle >= 0) {
				close(node.handle);
			}
		}
	
		// clean up the risp structure.
		risp_shutdown(risp);
	}
	
	return 0;
}


