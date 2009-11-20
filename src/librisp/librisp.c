//-----------------------------------------------------------------------------
// librisp
// see risp.h for details.
//-----------------------------------------------------------------------------



#include "risp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


#if (RISP_VERSION != 0x00010020)
#error "Incorrect header version.  code and header versions must match."
#endif


#if (RISP_MAX_USER_CMD > 256)
#error "Command can only be 1 byte."
#endif




//-----------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to 
// a risp_t structure that has been allocated and initialised.
risp_t *risp_init(void)
{
	risp_t *risp;

	// if our risp_char_t type is not actually 1 byte, not sure what would happen.
	assert(sizeof(risp_command_t) == 1);
	assert(RISP_MAX_USER_CMD <= 256);

	// allocate memory for the main struct.
	risp = (risp_t *) malloc(sizeof(risp_t));
	assert(risp != NULL);
	if (risp != NULL) {
		risp->invalid = NULL;
		memset(risp->commands, 0, (RISP_MAX_USER_CMD*sizeof(void *)));
	}
	
	return(risp);
}



//-----------------------------------------------------------------------------
// Clean up the structure that were created by the library.  
void risp_shutdown(risp_t *risp)
{
	assert(risp != NULL);
	memset(risp->commands, 0, (RISP_MAX_USER_CMD*sizeof(void *)));
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
	
	assert(risp->commands != NULL);
	assert(risp->commands[command] == NULL);
	
	if (risp->commands[command] == NULL) {
		risp->commands[command] = callback;
	}
}



//-----------------------------------------------------------------------------
// Add a command to our tables.  Since we are using an array of function 
// pointers, risp does not know definitively that the function specified 
// expects the correct parameters.  If the callback function is not the correct 
// type for the command-style, then it will generally end up with a segfault.
void risp_add_invalid(risp_t *risp, void *callback) 
{
	assert(risp != NULL);
	assert(callback != NULL);
	
	assert(risp->invalid == NULL);
	risp->invalid = callback;
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
	void (*func_inv)(void *base, const void *data, const risp_length_t length) = risp->invalid;
	
	
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
				
				func_nul = risp->commands[cmd];
				if (func_nul) 		 (*func_nul)(base);
				else if (func_inv) (*func_inv)(base, ptr, left);
				ptr++;
				left--;
				break;
				
			case 2:
				// 64 to 95		1 byte param
				if (left > 1) {
					func_int = risp->commands[cmd];
					if (func_int) {
						value = (unsigned char) ptr[1];
						(*func_int)(base, value);
					}
					else if (func_inv) (*func_inv)(base, ptr, left);
					ptr += 2;
					left -= 2;
				}
				else { cont = 0; }
				break;
				
			case 3:
				// 96 to 127		2 byte param
				if (left > 2) {
					func_int = risp->commands[cmd];
					if (func_int) {
						value = ((unsigned char) ptr[1] << 8) + 
									  ((unsigned char) ptr[2]);
						(*func_int)(base, value);
					}
					else if (func_inv) (*func_inv)(base, ptr, left);
					ptr += 3;
					left -= 3;
				}
				else { cont = 0; }
				break;
				
			case 4:
				// 128 to 159		4 byte param
				if (left > 4) {
					func_int = risp->commands[cmd];
					if (func_int) {
						value = ((unsigned char) ptr[1] << 24) +
										((unsigned char) ptr[2] << 16) +
										((unsigned char) ptr[3] << 8) +
										((unsigned char) ptr[4]);
						(*func_int)(base, value);
					}
					else if (func_inv) (*func_inv)(base, ptr, left);
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
						func_str = risp->commands[cmd];
						if (func_str) 		 (*func_str)(base, length, ptr+2);
						else if (func_inv) (*func_inv)(base, ptr, left);
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
						func_str = risp->commands[cmd];
						if (func_str)      (*func_str)(base, length, ptr+3);
						else if (func_inv) (*func_inv)(base, ptr, left);
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
						func_str = risp->commands[cmd];
						if (func_str) 	   (*func_str)(base, length, ptr+5);
						else if (func_inv) (*func_inv)(base, ptr, left);
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
