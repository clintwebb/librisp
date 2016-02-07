//-----------------------------------------------------------------------------
// Example of a librisp protocol handler.
//
// With this standalone example, we will be getting a file from the rfx server.
//
// Normally with a socket based stream, we would have some information about 
// that socket, at the very least, a handle to it.  We would also want to keep 
// a buffer for any data that is incomplete, waiting for more.  

#include <expbuf.h>
#include <risp.h>

#include "bufadd.h"
#include "rfx_prot.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>


static int sigtrap = 0;

#define INVALID_HANDLE -1


// The node structure.  This should be modified to fit your needs, but there 
// should be one for each socket connection that is being processed.  When 
// processing the data stream, the library is not responsible for data that is 
// incomplete.  It will be up to you to make sure that incomplete data is 
// added to a buffer, and re-processed when new data becomes available.
typedef struct {
	int handle;
	expbuf_t in, out;
	int verbose;
	int finished;
	data_t data;

	// local file handling.
	int filehandle;
	unsigned int size, offset;
} node_t;




// The server is sending us a file.
void processPut(node_t *node)
{
	char filename[256];
	int flen;
	
	assert(node != NULL);

	if (node->filehandle == INVALID_HANDLE) {
		// we haven't opened the file yet.

		assert(node->size == 0);
		assert(node->offset == 0);

		if (node->data.file.length == 0 || node->data.size == 0 || node->data.offset != 0) {
			// the client did not provide the required details.
			addCmd(&node->out, CMD_CLEAR);
			addCmd(&node->out, CMD_FAIL);
			addCmd(&node->out, CMD_EXECUTE);
		}
		else {
			// we have the necessary details.

			strncpy(filename, node->data.file.data, node->data.file.length);
			filename[node->data.file.length] = '\0';
			node->filehandle = open(filename, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
			
			if (node->filehandle < 0) {
				if (node->verbose) printf("node:%d - unable to open file: %s\n", node->handle, filename);
				addCmd(&node->out, CMD_CLEAR);
				addCmd(&node->out, CMD_FAIL);
				addCmd(&node->out, CMD_EXECUTE);
				
				node->filehandle = INVALID_HANDLE;
			}
			else {
				node->size = node->data.size;
				node->offset = 0;
			}
		}
	}

	if (node->filehandle != INVALID_HANDLE) {
	
	//	if (node->verbose) printf("node:%d - sending file: %s\n", node->handle, filename);
				
		if (node->offset != node->data.offset) {
			if (node->verbose) printf("node:%d - offset mismatch\n", node->handle);
			addCmd(&node->out, CMD_CLEAR);
			addCmd(&node->out, CMD_FAIL);
			addCmd(&node->out, CMD_EXECUTE);

			close(node->filehandle);
			node->filehandle = INVALID_HANDLE;
			node->offset = 0;
			node->size = 0;
		}
		else {
				
			// get the data and write it to the file.
			flen = write(node->filehandle, node->data.data.data, node->data.data.length);
			assert(flen < 0 || flen == node->data.data.length);
			if (flen < 0) {
				// something happened... unable to write to file.
				if (node->verbose) printf("node:%d - unable to write.\n", node->handle);
			}
			else {
				node->offset += flen;
				assert(node->offset <= node->size);
				if (node->offset == node->size) {
					printf("Finished file.\n");
					close(node->filehandle);
					node->filehandle = INVALID_HANDLE;
					node->offset = 0;
					node->size = 0;
					node->finished = 1;
				}
			}
		}
	}
}





void cmdNop(node_t *ptr)
{
}

void cmdInvalid(void *base, void *data)
{
	// this callback is called if we have an invalid command.  We shouldn't be receiving any invalid commands.
	unsigned char *cast;
	cast = (unsigned char *) data;
	printf("Received invalid: [%d, %d, %d]\n", cast[0], cast[1], cast[2]);
	assert(0);
}

// This callback function is to be fired when the CMD_CLEAR command is 
// received.  It should clear off any data received and stored in variables 
// and flags.  In otherwords, after this is executed, the node structure 
// should be in a predictable state.
void cmdClear(node_t *ptr)
{
 	assert(ptr != NULL);
// 	printf("CLEAR\n");
	ptr->data.op = CMD_NOP;
	ptr->data.size = 0;
	ptr->data.offset = 0;
	expbuf_clear(&ptr->data.file);
	expbuf_clear(&ptr->data.data);
}


// This callback function is called when the CMD_EXECUTE command is received.  
// It should look at the data received so far, and figure out what operation 
// needs to be done on that data.  Since this is a simulation, and our 
// protocol doesn't really do anything useful, we will not really do much in 
// this example.   
void cmdExecute(node_t *ptr) 
{
	risp_length_t existing;
 	assert(ptr != NULL);
	
	existing = ptr->out.length;

// 	printf("EXECUTE (%d)\n", ptr->data.op);

	// here we check what the current operation is.
	switch(ptr->data.op) {
		case CMD_LIST:
// 			processList(ptr);
			break;

		case CMD_LISTING:
// 			processListing(ptr);
			break;
			
		case CMD_LISTING_DONE:
// 			processListingDone(ptr);
			break;

		case CMD_PUT:
 			processPut(ptr);
			break;

		case CMD_GET:
// 			processGet(ptr);
			break;

		default:
			// we should not have any other op than what we know about.
			assert(0);
			break;
	}
}


void cmdList(node_t *ptr)
{
//  	printf("CLEAR\n");
	assert(ptr != NULL);
	ptr->data.op = CMD_LIST;
}

void cmdListing(node_t *ptr)
{
 	assert(ptr != NULL);
	ptr->data.op = CMD_LISTING;
}

void cmdListingDone(node_t *ptr)
{
 	assert(ptr != NULL);
	ptr->data.op = CMD_LISTING_DONE;
}

void cmdPut(node_t *ptr)
{
// 	printf("PUT\n");
 	assert(ptr != NULL);
	ptr->data.op = CMD_PUT;
}

void cmdGet(node_t *ptr)
{
// 	printf("GET\n");
 	assert(ptr != NULL);
	ptr->data.op = CMD_GET;
}



void cmdSize(node_t *ptr, risp_int_t value)
{
	assert(ptr != NULL);
	ptr->data.size = value;
// 	printf("SIZE %d\n", value);
}

void cmdOffset(node_t *ptr, risp_int_t value)
{
	assert(ptr != NULL);
	ptr->data.offset = value;
// 	printf("OFFSET %d\n", value);
}



// This callback function is fired when we receive the CMD_URL command.  We 
// dont need to actually do anything productive with this, other than storing 
// the information into some internal variable.
void cmdFile(node_t *ptr, risp_length_t length, void *data)
{
	char filename[256];
	assert(ptr != NULL);
	assert(length >= 0);
	assert(length < 256);
	assert(data != NULL);
	expbuf_set(&ptr->data.file, data, length);
		
	strncpy(filename, (char *)data, length);
	filename[length] = '\0';
// 	printf("FILE \"%s\"\n", filename);

}

void cmdData(node_t *ptr, risp_length_t length, void *data)
{
	assert(ptr != NULL);
	assert(data != NULL);
	expbuf_set(&ptr->data.data, data, length);

// 	printf("DATA <%d>\n", length);
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
// 		int opts;
// 
// 		assert(nsock>0);
// 		opts = fcntl(nsock, F_GETFL);
// 		if (opts >= 0) {
// 				opts = (opts | O_NONBLOCK);
// 				fcntl(nsock, F_SETFL, opts);
// 		}
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
	int sent;
	char *srv = "127.0.0.1";
	char *filename = NULL;
	int port = DEFAULT_PORT;
	int avail;
	int processed;
	int len;
	int done = 0, t;

	node_t node;

	// initialise the node data.
	node.handle = INVALID_HANDLE;
	node.verbose = 0;
	node.finished = 0;
	expbuf_init(&node.in, 1024);
	expbuf_init(&node.out, 1024);
	expbuf_init(&node.data.file, 0);
	expbuf_init(&node.data.data, 0);
	node.data.op = CMD_NOP;
	node.data.size = 0;
	node.data.offset = 0;

	node.filehandle = INVALID_HANDLE;
	node.size = 0;
	node.offset = 0;


	while ((c = getopt(argc, argv, "f:p:s:v")) != -1) {
		switch (c) {
			case 'f':
				filename = optarg;
				assert(filename != NULL);
				break;
			case 'p':
				port = atoi(optarg);
				assert(port > 0);
				break;
			case 's':
				srv = optarg;
				assert(srv != NULL);
				break;
			case 'v':
				node.verbose ++;
				break;
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
		}
	}

	if (filename == NULL) {
		fprintf(stderr, "Need a filename.\n\n");
		exit(1);
	}

	// get an initialised risp structure.
	risp = risp_init();
	if (risp == NULL) {
		printf("Unable to initialise RISP library.\n");
	}
	else {
		risp_add_command(risp, CMD_CLEAR, 	&cmdClear);
		risp_add_command(risp, CMD_EXECUTE, &cmdExecute);
		risp_add_command(risp, CMD_OFFSET,  &cmdOffset);
		risp_add_command(risp, CMD_SIZE,    &cmdSize);
		risp_add_command(risp, CMD_FILE,    &cmdFile);
		risp_add_command(risp, CMD_DATA,    &cmdData);
		risp_add_command(risp, CMD_PUT,     &cmdPut);
		risp_add_command(risp, CMD_GET,     &cmdGet);
		
		len = strlen(filename);
		assert(len < 256);

		assert(node.out.length == 0);
		
		addCmd(&node.out, CMD_CLEAR);
		addCmd(&node.out, CMD_GET);
		addCmdShortStr(&node.out, CMD_FILE, len, filename);
		addCmd(&node.out, CMD_EXECUTE);
		
		// and process it a lot of time.
		printf("Sending request for: %s\n", filename);
		
		// connect to the remote socket.
		node.handle = sock_connect(srv, port);
		if (node.handle <= 0) {
			printf("Unable to connect to %s:%d\n", srv, port);
		}
		else {
			while (sigtrap == 0 && node.finished == 0) {

				// continue to send data to the socket over and over as quickly as possible.
				while (node.out.length > 0) {
					assert(node.handle > 0);
					sent = sock_send(node.handle, node.out.data, node.out.length);
					if (sent < 0) { sigtrap ++; }
					else {
						assert(sent > 0);
						assert(sent <= node.out.length);
						if (sent == node.out.length) { expbuf_clear(&node.out); }
						else { expbuf_purge(&node.out, sent); }
					}	
				}

				// if we didn't generate a fail during the write, then we do a read.
				if (sigtrap == 0) {

					avail = node.in.max - node.in.length;
					if (avail < 1024) {
						expbuf_shrink(&node.in, 1024);
						avail = 1024;
					}

					sent = sock_receive(node.handle, node.in.data + node.in.length, avail);
					if (sent < 0) { sigtrap ++; }
					else {
						assert(sent > 0);
						node.in.length += sent;
						assert(node.in.length <= node.in.max);
						if (sent == avail) {
							// we filled the incoming buffer, so we need to double it.
							expbuf_shrink(&node.in, node.in.max * 2);
						}
						processed = risp_process(risp, &node, node.in.length, (unsigned char *) node.in.data);
// 						printf("Processed %d.\n", processed);
						if (processed > 0) {
							expbuf_purge(&node.in, processed);

							if (node.offset > 0 && node.size > 0) {
								t = (node.offset / (node.size/100));
								if (t > done) {
									done = t;
									printf("Done - %c%d\n", '%', done);
								}
							}
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


