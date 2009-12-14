//-----------------------------------------------------------------------------
// librisp
// see risp.h for details.
//-----------------------------------------------------------------------------



#include "risp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


#if (RISP_VERSION != 0x00020000)
#error "Incorrect header version.  code and header versions must match."
#endif


#if (RISP_MAX_USER_CMD > 256)
#error "Command can only be 1 byte."
#endif




//-----------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to 
// a risp_t structure that has been allocated and initialised.
risp_t *risp_init(risp_t *risp)
{
	risp_t *r;
	int i;
	
	// if our risp_char_t type is not actually 1 byte, not sure what would happen.
	assert(sizeof(risp_command_t) == 1);
	assert(RISP_MAX_USER_CMD <= 256);

	// allocate memory for the main struct.
	if (risp == NULL) {
		r = (risp_t *) malloc(sizeof(risp_t));
		r->created_internally = 1;
	}
	else {
		r = risp;
		r->created_internally = 0;
	}
	
	assert(r != NULL);
	if (r != NULL) {
		for (i=0; i<RISP_MAX_USER_CMD; i++) {
			r->commands[i].handler = NULL;
			r->commands[i].set = 0;
			r->commands[i].length = 0;
			r->commands[i].max = 0;
			r->commands[i].buffer = NULL;
			r->commands[i].value = 0;
		}
	}
	
	return(risp);
}



//-----------------------------------------------------------------------------
// Clean up the structure that were created by the library.  
void risp_shutdown(risp_t *risp)
{
	int i;
	
	assert(risp != NULL);
	for (i=0; i<RISP_MAX_USER_CMD; i++) {
		risp->commands[i].handler = NULL;
		risp->commands[i].set = 0;
		if (risp->commands[i].buffer) {
			risp->commands[i].length = 0;
			risp->commands[i].max = 0;
			free(risp->commands[i].buffer);
			risp->commands[i].buffer = NULL;
		}
	}
	
	assert(risp->created_internally == 1 | risp->created_internally == 0);
	if (risp->created_internally == 1) {
		free(risp);
	}
}



//-----------------------------------------------------------------------------
// This function is used to reduce the amount of memory that is used in 
// buffers.  It goes through the array, and resizes all memor buffers to the 
// current length.  This means that if a buffer was allocated, but is currently 
// empty, it will be deallocated.
void risp_flush(risp_t *risp)
{
	int i;
	
	for (i=0; i<RISP_MAX_USER_CMD; i++) {
		
		// we only care about commands that dont have a handler, because if it 
		// had a handler, then we wouldn't be buffering data.
		if (risp->commands[i].handler == NULL) {
			
			// if there is currently a buffer set.
			if (risp->commands[i].buffer) {
				assert(risp->commands[i].max > 0);
				
				if (risp->commands[i].set > 0) {
					// the buffer currently has live data in it, so we can only 
					// reduce it, and cannot free all of it.
					
					if (risp->commands[i].length < risp->commands[i].max) {
						risp->commands[i].buffer = realloc(risp->commands[i].buffer, risp->commands[i].length);
						assert(risp->commands[i].buffer);
						risp->commands[i].max = risp->commands[i].length;
					}
				}
				else {
					// the buffer is not currently set, so we can free the 
					// entire thing.
					
					risp->commands[i].max = 0;
					risp->commands[i].length = 0;
					free(risp->commands[i].buffer);
					risp->commands[i].buffer = NULL;
					risp->commands[i].value = 0;
				}
			}
		}
	}
}



//-----------------------------------------------------------------------------
// This function will clear all the buffered values.
void risp_clear_all(risp_t *risp)
{
	int i;
	
	assert(risp);
	
	for (i=0; i<RISP_MAX_USER_CMD; i++) {
		if (risp->commands[i].set > 0) {
			risp->commands[i].set = 0;
			risp->commands[i].length = 0;
			risp->commands[i].value = 0;
		}
	}
}


//-----------------------------------------------------------------------------
// reset the data for a particular command.  It does not dissolve any memory 
// allocated.  It merely resets the length and 'set' values;
void risp_clear(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(risp->commands[command].handler == NULL);
	risp->commands[command].set = 0;
	risp->commands[command].length = 0;
	risp->commands[command].value = 0;
}



//-----------------------------------------------------------------------------
// Add a command to our tables.  Since we are using an array of function 
// pointers, risp does not know definitively that the function specified 
// expects the correct parameters.  If the callback function is not the correct 
// type for the command-style, then it will generally end up with a segfault.
void risp_add_command(risp_t *risp, risp_command_t command, void *callback) 
{
	assert(risp != NULL);
	assert(command >= 0);
	assert(command < RISP_MAX_USER_CMD);
	assert(callback != NULL);
	
	assert(risp->commands[command].handler == NULL);
	risp->commands[command].handler = callback;
	risp->commands[command].set = 0;
	risp->commands[command].length = 0;
	risp->commands[command].max = 0;
	risp->commands[command].buffer = NULL;
	risp->commands[command].value = 0;
}




//-----------------------------------------------------------------------------
// Process all the commands in the data buffer.  If we dont have enough data to 
// complete the operation, then we return the number of bytes that we did not 
// process.  The calling function can then figure out what to do with it.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t len, const void *data)
{
	risp_length_t left, length;
	const unsigned char *ptr;
	risp_command_t cmd;
	unsigned char style;
	risp_int_t value;
	int cont = 1;
	
	// callback function prototypes.
	void (*func_nul)(void *base) = NULL;
	void (*func_int)(void *base, const risp_int_t value) = NULL;
	void (*func_str)(void *base, const risp_length_t length, const void *data) = NULL;
	
	
// 	assert(risp != NULL);
// 	assert(risp->commands != NULL);
// 	assert(len > 0);
// 	assert(data != NULL);
	
	left = len;
	ptr = (char *) data;
	
	while(cont != 0 && left > 0) {
	
		// NOTE: Even though we could check outside the switch to see if we have a
		//       handler for the command, we still need to increment the pointer, 
		//       even if we cannot process the command.  So it will execute only 
		//       if there is a handler, but otherwise will be processed.
		
		cmd = *ptr;
		style = cmd >> 5;
		switch(style) {
			case 0:
			case 1:
				// 0 to 63			No param
				
				func_nul = risp->commands[cmd].handler;
				if (func_nul) 		 (*func_nul)(base);
				else { risp->commands[cmd].set = 1; }
				ptr++;
				left--;
				break;
				
			case 2:
				// 64 to 95		1 byte param
				if (left > 1) {
					func_int = risp->commands[cmd].handler;
					if (func_int) {
						value = (unsigned char) ptr[1];
						(*func_int)(base, value);
					}
					else {
						risp->commands[cmd].set = 1;
						risp->commands[cmd].value = value; 
					}
					ptr += 2;
					left -= 2;
				}
				else { cont = 0; }
				break;
				
			case 3:
				// 96 to 127		2 byte param
				if (left > 2) {
					func_int = risp->commands[cmd].handler;
					if (func_int) {
						value = ((unsigned char) ptr[1] << 8) + 
									  ((unsigned char) ptr[2]);
						(*func_int)(base, value);
					}
					else {
						risp->commands[cmd].set = 1;
						risp->commands[cmd].value = value; 
					}
					ptr += 3;
					left -= 3;
				}
				else { cont = 0; }
				break;
				
			case 4:
				// 128 to 159		4 byte param
				if (left > 4) {
					func_int = risp->commands[cmd].handler;
					if (func_int) {
						value = ((unsigned char) ptr[1] << 24) +
										((unsigned char) ptr[2] << 16) +
										((unsigned char) ptr[3] << 8) +
										((unsigned char) ptr[4]);
						(*func_int)(base, value);
					}
					else {
						risp->commands[cmd].set = 1;
						risp->commands[cmd].value = value; 
					}
					ptr += 5;
					left -= 5;
				}
				else { cont = 0; }
				break;

			case 5:
				// 160 to 191	 1 byte length + data
				if (left > 1) {
					length = ptr[1];
					if (left > 1 + length) {
						func_str = risp->commands[cmd].handler;
						if (func_str) 		 (*func_str)(base, length, ptr+2);
						else {
							if (risp->commands[cmd].max < length) {
								risp->commands[cmd].max = length;
								risp->commands[cmd].buffer = realloc(risp->commands[cmd].buffer, length);
							}
							memcpy(risp->commands[cmd].buffer, ptr+2, length);
							risp->commands[cmd].length = length;
							risp->commands[cmd].set = 1;
						}
						ptr += (2 + length);
						left -= (2 + length);
					}
					else { cont = 0; }
				}
				else { cont = 0; }
				break;
				
			case 6:
				// 192 to 223	 2 byte length + data
				if (left > 2) {
					length = ((unsigned char) ptr[1] << 8) + 
								   ((unsigned char) ptr[2]);
					if (left > 2 + length) {
						func_str = risp->commands[cmd].handler;
						if (func_str)      (*func_str)(base, length, ptr+3);
						else {
							if (risp->commands[cmd].max < length) {
								risp->commands[cmd].max = length;
								risp->commands[cmd].buffer = realloc(risp->commands[cmd].buffer, length);
							}
							memcpy(risp->commands[cmd].buffer, ptr+3, length);
							risp->commands[cmd].length = length;
							risp->commands[cmd].set = 1;
						}
						ptr += (3 + length);
						left -= (3 + length);
					}
					else { cont = 0; }
				}
				else { cont = 0; }
				break;
				
			case 7:
				// 224 to 255 	4 byte length + data
				if (left > 4) {
					length = ((unsigned char) ptr[1] << 24) +
									 ((unsigned char) ptr[2] << 16) +
									 ((unsigned char) ptr[3] << 8) +
									 ((unsigned char) ptr[4]);
					if (left > 4 + length) {
						func_str = risp->commands[cmd].handler;
						if (func_str) 	   (*func_str)(base, length, ptr+5);
						else {
							if (risp->commands[cmd].max < length) {
								risp->commands[cmd].max = length;
								risp->commands[cmd].buffer = realloc(risp->commands[cmd].buffer, length);
							}
							memcpy(risp->commands[cmd].buffer, ptr+5, length);
							risp->commands[cmd].length = length;
							risp->commands[cmd].set = 1;
						}
						ptr += (5 + length);
						left -= (5 + length);
					}
					else { cont = 0; }
				}
				else { cont = 0; }
				break;
				
				
			default:
				assert(1);
				break;
		}	
	}	
	
// 	assert(left <= len);
// 	assert(left >= 0);
	assert(len - left >= 0);	

	return(len - left);
}


// return 0 if not set, 1 if it is.
int risp_isset(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(risp->commands[command].handler == NULL);
	return(risp->commands[command].set);
}


int risp_getvalue(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(risp->commands[command].handler == NULL);
	return(risp->commands[command].value);
}

unsigned int risp_getlength(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(risp->commands[command].handler == NULL);
	assert(risp->commands[command].length <= risp->commands[command].max);
	return(risp->commands[command].length);
}


char * risp_getdata(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(risp->commands[command].handler == NULL);
	assert(risp->commands[command].length <= risp->commands[command].max);
	assert(risp->commands[command].buffer);
	return(risp->commands[command].buffer);
}


