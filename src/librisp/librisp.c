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




//-----------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to 
// a risp_t structure that has been allocated and initialised.
risp_t *risp_init(void)
{
	risp_t *risp;

	// if our risp_char_t type is not actually 1 byte, not sure what would happen.
	assert(sizeof(risp_char_t) == 1);

	// allocate memory for the main struct.
	risp = (risp_t *) malloc(sizeof(risp_t));
	assert(risp != NULL);
	if (risp != NULL) {
		memset(risp->commands, 0, (RISP_MAX_USER_CMD*sizeof(void *)));
	}
	
	return(risp);
}



//-----------------------------------------------------------------------------
// Clean up the structure that were created by the library.  
risp_result_t risp_shutdown(risp_t *risp)
{
	assert(risp != NULL);
	memset(risp->commands, 0, (RISP_MAX_USER_CMD*sizeof(void *)));
	return(SUCCESS);
}


//-----------------------------------------------------------------------------
// Add a command to our tables.  Since we are using an array of function 
// pointers, risp does not know definitively that the function specified 
// expects the correct parameters.  If the callback function is not the correct 
// type for the command-style, then it will generally end up with a segfault.
risp_result_t risp_add_command(risp_t *risp, risp_command_t command, void *callback) 
{
	assert(risp != NULL);
	assert(command > 0);
	assert(command < RISP_MAX_USER_CMD);
	assert(callback != NULL);
	
	assert(risp->commands != NULL);
	assert(risp->commands[command] == NULL);
	
	if (risp->commands[command] == NULL) {
		risp->commands[command] = callback;
		return(SUCCESS);
	}
	else {
		return(FAILED);
	}	
}



//-----------------------------------------------------------------------------
// Process all the commands in the data buffer.  If we dont have enough data to 
// complete the operation, then we return the number of bytes that we did not 
// process.  The calling function can then figure out what to do with it.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t len, risp_char_t *data)
{
	risp_length_t left, length;
	risp_char_t *ptr;
	risp_char_t cmd, style;
	risp_int_t value;
	int cont = 1;
	
	// callback function prototypes.
	void (*func_null)(void *base) = NULL;
	void (*func_int)(void *base, risp_int_t value) = NULL;
	void (*func_str)(void *base, risp_length_t length, void *data) = NULL;
	
	assert(risp != NULL);
	assert(risp->commands != NULL);
	assert(len > 0);
	assert(data != NULL);
	
	left = len;
	ptr = data;
	
	while(cont != 0 && left > 0) {
	
		// get the command.
		cmd = *ptr;
		
		// determine the type (bitshift by 5 bits to the right)
		style = cmd >> 5;
		assert(style >= 0 && style <= 7);
		
		// NOTE: Even though we could check outside the switch to see if we have a 
		//       handler for the command, we still need to increment the pointer, 
		//       even if we cannot process the command.  So it will execute only 
		//       if there is a handler, but otherwise will be processed.
		
		switch(style) {
			case 0:
				// 0 to 31			No param
				if (risp->commands[cmd] != NULL) {
					func_null = risp->commands[cmd];
					(*func_null)(base);
				}
				ptr++;
				left--;
				break;
				
			case 1:
				// 32 to 63		1 byte param
				if (left > 1) {
					if (risp->commands[cmd] != NULL) {
						func_int = risp->commands[cmd];
						value = (unsigned char) ptr[1];
						(*func_int)(base, value);
					}
					ptr += 2;
					left -= 2;
				}
				else { cont = 0; }
				break;
				
			case 2:
				// 64 to 95		2 byte param
				if (left > 2) {
					if (risp->commands[cmd] != NULL) {
						func_int = risp->commands[cmd];
						value = ((unsigned char) ptr[1] << 8) + 
									  ((unsigned char) ptr[2]);
						(*func_int)(base, value);
					}
					ptr += 3;
					left -= 3;
				}
				else { cont = 0; }
				break;
				
			case 3:
				// 96 to 127		4 byte param
				if (left > 4) {
					if (risp->commands[cmd] != NULL) {
						func_int = risp->commands[cmd];
						value = ((unsigned char) ptr[1] << 24) +
										((unsigned char) ptr[2] << 16) +
										((unsigned char) ptr[3] << 8) +
										((unsigned char) ptr[4]);
						(*func_int)(base, value);
					}
					ptr += 5;
					left -= 5;
				}
				else { cont = 0; }
				break;

			case 4:
				// 128 to 159	1 byte length + data
				if (left > 1) {
					length = ptr[1];
					if (left > 1 + length) {
						if (risp->commands[cmd] != NULL) {
							func_str = risp->commands[cmd];
							(*func_str)(base, length, ptr+2);
						}
						ptr += (2 + length);
						left -= (2 + length);
					}
					else { cont = 0; }
				}
				else { cont = 0; }
				break;
				
			case 5:
				// 160 to 191	2 byte length + data
				if (left > 2) {
					length = ((unsigned char) ptr[1] << 8) + 
								   ((unsigned char) ptr[2]);
					if (left > 2 + length) {
						if (risp->commands[cmd] != NULL) {
							func_str = risp->commands[cmd];
							(*func_str)(base, length, ptr+3);
						}
						ptr += (3 + length);
						left -= (3 + length);
					}
					else { cont = 0; }
				}
				else { cont = 0; }
				break;
				
			case 6:
			case 7:
				// 192 to 223	4 byte length + data
				if (left > 4) {
					length = ((unsigned char) ptr[1] << 24) +
									 ((unsigned char) ptr[2] << 16) +
									 ((unsigned char) ptr[3] << 8) +
									 ((unsigned char) ptr[4]);
					if (left > 4 + length) {
						if (risp->commands[cmd] != NULL) {
							func_str = risp->commands[cmd];
							(*func_str)(base, length, ptr+5);
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
	
	return(left);
}
