// Example of a librisp protocol handler.

#include <risp.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
	int handle;
	char *buffer;
	int length;
	
	char url[256];
	int ttl;

} node_t;


#define CMD_NOP			0
#define CMD_CLEAR		1
#define CMD_EXECUTE	2
#define CMD_TTL     32
#define CMD_URL			128


void cmdClear(void *base) 
{
	node_t *ptr = (node_t *) base;
	assert(ptr != NULL);
	ptr->url[0] = '\0';
	ptr->ttl = 0;
}

void cmdExecute(void *base) 
{
	node_t *ptr = (node_t *) base;
	assert(ptr != NULL);
//  	printf("Execute!  (url: '%s', ttl: %d)\n", ptr->url, ptr->ttl);
}

void cmdURL(void *base, risp_length_t length, risp_char_t *data) 
{
	node_t *ptr = (node_t *) base;
	
	assert(base != NULL);
	assert(length >= 0);
	assert(data != NULL);
	assert(length < 256);

	memcpy(ptr->url, data, length);
	ptr->url[length] = '\0';
}

void cmdTtl(void *base, risp_int_t value) 
{
	node_t *ptr = (node_t *) base;
	assert(base != NULL);
	assert(value >= 0 && value < 256);
	
	ptr->ttl = value;
}

int main(void)
{
	risp_t *risp;
	char buff[20];
	risp_length_t leftover;
	int count, j;

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
		buff[2] = 4;
		buff[3] = 'h';
		buff[4] = 't';
		buff[5] = 't';
		buff[6] = 'p';
		buff[7] = CMD_TTL;
		buff[8] = (unsigned char) 15;
		buff[9] = CMD_EXECUTE;
		buff[10] = CMD_TTL;
		buff[11] = (unsigned char) 30;
		buff[12] = CMD_EXECUTE;
		buff[13] = CMD_CLEAR;
		buff[14] = CMD_EXECUTE;
		buff[15] = CMD_CLEAR;
		
		// and process it a lot of time.
 		for(j=0; j<10000000; j++) {
			leftover = risp_process(risp, &node, 16, buff);
 		}
		
		printf("finished processing.  left:%d\n", leftover);
 		assert(leftover == 0);
	
		// clean up the risp structure.
		risp_shutdown(risp);
	}
	
	return 0;
}


