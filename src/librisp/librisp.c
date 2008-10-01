//-----------------------------------------------------------------------------
// librisp
// see librisp.h for details.
//-----------------------------------------------------------------------------



#include "librisp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


#if (RISP_MAX_USER_CMD > 256)
#error Command can only be 1 byte.
#endif

#if (sizeof(risp_char_t) != 1)
#error make sure our risp_char_t type is actually 1 byte.  Not sure what would happen if it was more than one.
#endif

// pre-declare our internal functions
static risp_length_t risp_process(risp_t *risp, int handle, risp_length_t len, risp_char_t *data);


//-----------------------------------------------------------------------------
// Initialise everything we need to initialise.
risp_t *risp_init(void)
{
	risp_t *risp;

	// allocate memory for the main struct.
	risp = (risp_t *) malloc(sizeof(risp_t));
	assert(risp != NULL;
	
	risp->commands = (void **) malloc(RISP_MAX_USER_CMD*sizeof(void *));
	risp->buffer = NULL;
	risp->buffer_count = 0;
	
	memset(risp->commands, 0, RISP_MAX_USER_CMD*sizeof(void *));
	
	return(risp);
}



//-----------------------------------------------------------------------------
// Clean up the buffers that were created by the library.  In otherwords, 
// prepare for an orderly shutdown of the application.
risp_result_t risp_shutdown(risp_t *risp)
{
	assert(risp != NULL);
	free(risp);
	return(SUCCESS);
}


//-----------------------------------------------------------------------------
// Add a command to our tables.  Since we are using an array of function 
// pointers, all the functions need to be of the same type, which makes it a 
// bit cumbersome for some... 
risp_result_t risp_add_command(risp_t *risp, risp_command_t command, void (*callback)(void *base, risp_length_t length, risp_char_t *data)) 
{
	assert(risp != NULL);
	
	// make sure that it is not one of the reserved commands;
	assert(command > 0);
	assert(command < RISP_MAX_USER_CMD);
	
	if (risp->commands[command] == NULL) {
		risp->commands[command] = callback;
		return(SUCCESS);
	}
	else {
		assert(risp->commands[command] == NULL);
		return(FAILED);
	}	
}

//-----------------------------------------------------------------------------
// Add and process data.  Data will be added to any existing data that was not 
// able to be processed.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t length, risp_char_t *data)
{
	risp_length_t leftover;

	assert(risp != NULL);
	assert(length > 0);
	assert(data != NULL);
	
		leftover = risp_process(handle, length, data);
		assert(leftover <= length);
		
		if (leftover > 0) {
			_risp_buffer = (void *) malloc(leftover);
			assert(_risp_buffer != NULL);
			memcpy(_risp_buffer, &data[length-leftover], leftover);
			_risp_buffer_len = leftover;
		}
	}	

	return(leftover);
}



//-----------------------------------------------------------------------------
// Commands can be packed in other commands (compressed or authorised 
// operations for example).   We need to expand and process those commands 
// before continuing the existing incoming stream.
risp_length_t risp_expand(int handle, risp_length_t len, risp_char_t *data)
{
	assert(handle > 0);
	assert(len > 0);
	assert(data != NULL);

	return(FAILED);
}


//-----------------------------------------------------------------------------
// Process all the commands in the data buffer.  If we didn't have enough data 
// to complete the operation, then we return the number of bytes that we did 
// not process.  The calling function can then figure out what to do with it.
static risp_length_t risp_process(int handle, risp_length_t len, risp_char_t *data)
{
	risp_length_t index, left, length;
	risp_char_t *ptr;
	risp_char_t cmd, style;
	risp_page_t page;
	int offset;
	bool cont = false;
	
	assert(handle > 0);
	assert(len > 0);
	assert(data != NULL);
	
	index = 0;
	left = len;
	ptr = data;
	page = 0;
	
	while(cont != false) {
		// get the command.
		cmd = *ptr;
		
		// determine the type (bitshift by 5 bits to the right)
		style = cmd >> 5;
		assert(style >= 0 && style <= 7);
		
		switch(style) {
			case 0:
				// 0 to 31			No param
				assert(page < _risp_max_pages);
				offset = (page * RISP_MAX_USER_CMD) + cmd;
				_risp_pages[offset]( int handle, 0, NULL);
				break;
				
// 32 to 63		1 byte param
// 64 to 95		2 byte param
// 96 to 127		4 byte param
// 128 to 159	1 byte length + data
// 160 to 191	2 byte length + data
// 192 to 223	4 byte length + data

// 224	to 255	4 byte length + data [ reserved ]

		}	
		// if we still have enough data to begin processing the command, then we call the callback
		
		// increment the pointer.
		
	}	
	
	return(left);
}
