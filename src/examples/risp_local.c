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

#include "risp_server_prot.h"

unsigned int statOps = 0;
unsigned int statCmd = 0;
unsigned int statBytes = 0;

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
	char url[256];
	int ttl;

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
	ptr->url[0] = '\0';
	ptr->ttl = 0;

	statCmd ++;
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
	
	statOps ++;
	statCmd ++;

	// All we can do really in this exercise is to print out the values that we have.
//  	printf("Execute!  (url: '%s', ttl: %d)\n", ptr->url, ptr->ttl);
}

// This callback function is fired when we receive the CMD_URL command.  We 
// dont need to actually do anything productive with this, other than storing 
// the information into some internal variable.
void cmdURL(void *base, risp_length_t length, risp_char_t *data) 
{
	node_t *ptr = (node_t *) base;
	
	// At every opportunity, we need to make sure that our data is legit.
	assert(base != NULL);
	assert(length >= 0);
	assert(data != NULL);
	assert(length < 256);

	// copy the string that was provides from the stream (which is guaranteed to 
	// be complete)
	memcpy(ptr->url, data, length);
	ptr->url[length] = '\0';

	statCmd ++;
}

void cmdTtl(void *base, risp_int_t value) 
{
	node_t *ptr = (node_t *) base;
	assert(base != NULL);
	assert(value >= 0 && value < 256);
	
	ptr->ttl = value;
	statCmd ++;
}

int main(int argc, char **argv)
{
	risp_t *risp;
	char buff[100];
	risp_length_t leftover;
	int count, j;
	int limit = 10000;

	if (argc > 1) {
		limit = atoi(argv[1]);
	}

	node_t node;

	node.handle = 0;
	node.buffer = NULL;
	node.length = 0;

	// get an initialised risp structure.
	risp = risp_init();
	if (risp == NULL) {
		printf("Unable to initialise RISP library.\n");
	}
	else {
		risp_add_command(risp, CMD_CLEAR, 	&cmdClear);
		risp_add_command(risp, CMD_EXECUTE, &cmdExecute);
		risp_add_command(risp, CMD_TTL,     &cmdTtl);
		risp_add_command(risp, CMD_URL, 		&cmdURL);
		
		// clear our base out... just to be sure.
		cmdClear(&node);
		
		// build the operation that we want to send.	
		buff[0] = CMD_CLEAR;
		buff[1] = CMD_URL;
		buff[2] = (unsigned char) 17;
		buff[3] = 'h';
		buff[4] = 't';
		buff[5] = 't';
		buff[6] = 'p';
		buff[7] = ':';
		buff[8] = '/';
		buff[9] = '/';
		buff[10] = 'r';
		buff[11] = 'h';
		buff[12] = 'o';
		buff[13] = 'k';
		buff[14] = 'z';
		buff[15] = '.';
		buff[16] = 'c';
		buff[17] = 'o';
		buff[18] = 'm';
		buff[19] = '/';
		buff[20] = CMD_TTL;
		buff[21] = (unsigned char) 15;
		buff[22] = CMD_EXECUTE;
		buff[23] = CMD_TTL;
		buff[24] = (unsigned char) 30;
		buff[25] = CMD_EXECUTE;
		buff[26] = CMD_CLEAR;
		buff[27] = CMD_EXECUTE;
		buff[28] = CMD_CLEAR;
		
		// and process it a lot of time.
		printf("Processing data stream (x%d)\n", limit);
		
		leftover = risp_process(risp, &node, 15, buff);
		assert(leftover > 0);
		leftover = risp_process(risp, &node, 28, &buff[1]);
		assert(leftover == 0);
		
 		for(j=0; j<limit; j++) {
 			statBytes += 29;
			leftover = risp_process(risp, &node, 29, buff);
 		}
		printf("Complete.\nCommands: %u\nOperations: %u\nBytes: %u\n\n", statCmd, statOps, statBytes);
 		assert(leftover == 0);
	
		// clean up the risp structure.
		risp_shutdown(risp);
	}
	
	return 0;
}


