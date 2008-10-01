// Example of a librisp protocol handler.

#include <risp.h>
#include <stdio.h>
#include <assert.h>


#define CMD_NOP			0
#define CMD_CLEAR		1
#define CMD_EXECUTE	2
#define CMD_URL			128

static char *url = NULL;


void cmdClear(int handle, risp_length_t length, risp_char_t *data) 
{
	assert(handle >= 0 && length == 0 && data == NULL);
	if (url != NULL) { free(url); url = NULL; }
	printf("Clear!\n");
}

void cmdExecute(int handle, risp_length_t length, risp_char_t *data) 
{
	assert(handle >= 0 && length == 0 && data == NULL);
	printf("Execute!  (url: '%s')\n", url?url:"");
}

void cmdURL(int handle, risp_length_t length, risp_char_t *data) 
{
	assert(handle >= 0);
	assert(length >= 0);
	assert(data != NULL);

	if (url != NULL) { free(url); }
	url = malloc(length + 1);
	memcpy(url, data, length);
	url[length] = '\0';
	printf("Store URL: '%s'\n", url);
}


int main(void)
{
	risp_t *risp;
	char buff[20];

	// get an initialised risp structure.
	risp = risp_init();

	risp_add_command(CMD_CLEAR, &cmdClear);
	risp_add_command(CMD_EXECUTE, &cmdExecute);
	risp_add_command(CMD_URL, &cmdURL);

	buff[0] = CMD_CLEAR;
	buff[1] = CMD_URL;
	buff[2] = 4;
	strcpy(&buff[3], "http");
	buff[7] = CMD_EXECUTE;
	buff[8] = CMD_CLEAR;
	risp_data(0, 8. buff);

	// indicate that we are not getting any more data for this handle.
	risp_cleanup(0);

	// clean up the risp structure.
	risp_shutdown(risp);

	return 0;
}


