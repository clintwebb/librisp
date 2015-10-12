//-----------------------------------------------------------------------------
/*
    librisp64
    see risp64.h for details.
    Copyright (C) 2015  Clinton Webb
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


*/
//-----------------------------------------------------------------------------



#include "risp64.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>


#if (RISP_VERSION != 0x00030000)
#error "Incorrect header version.  code and header versions must match."
#endif


#if (RISP_MAX_USER_CMD > 256)
#error "Command can only be 1 byte."
#endif





// 'functions' to convert 64-bit longs between host-byte-order and network-byte-order.
#define htonll(x) ((1==htonl(1)) ? (x) : ((unsigned long long)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((unsigned long long)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))


//-----------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to 
// a risp_t structure that has been allocated and initialised.  If the 
// parameter is NULL, it will allocate space.  If a pointer param is provided, 
// it will initialize that space instead.
risp_t *risp_init(risp_t *risp)
{
	risp_t *r;
	int i;


	// Assume some sane type sizes.    
	assert(sizeof(int) == 4);
	assert(sizeof(long) == sizeof(int));
	assert(sizeof(long long) == 8);

	
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
	
	
	// we could simply memset the entire space, however, for completeness and to make it easier if 
	// we add structure items later on that require something other than zero.
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
	
	return(r);
}



//-----------------------------------------------------------------------------
// Clean up the structure that were created by the library.  
risp_t * risp_shutdown(risp_t *risp)
{
	int i;
	
	assert(risp != NULL);
	for (i=0; i<RISP_MAX_USER_CMD; i++) {
		risp->commands[i].handler = NULL;
		risp->commands[i].set = 0;
		risp->commands[i].value = 0;
		if (risp->commands[i].buffer) {
			risp->commands[i].length = 0;
			risp->commands[i].max = 0;
			free(risp->commands[i].buffer);
			risp->commands[i].buffer = NULL;
		}
	}
	
	assert(risp->created_internally == 1 | risp->created_internally == 0);
	if (risp->created_internally == 0) {
		// risp structure was not created internally, caller must take care of it.
		return(NULL);
	}
	else {
		// we allocated the space, so we need to free it.
		free(risp);
		return(risp);
	}
}



//-----------------------------------------------------------------------------
// This function is used to reduce the amount of memory that is used in 
// buffers.  It goes through the array, and resizes all memory buffers to the 
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
// This function will clear all the buffered values.
void risp_clear_all(risp_t *risp)
{
	int i;
	
	assert(risp);
	
	for (i=0; i<RISP_MAX_USER_CMD; i++) {
		if (risp->commands[i].set > 0) {
			risp_clear(risp, i);
		}
	}
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




//--------------------------------------------------------------------------------------------------
// Process all the commands in the data buffer, returning the number of bytes processed.  If we dont 
// have enough data to complete the operation, then the calling function can then figure out what to 
// do with it.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t len, const void *data)
{
	risp_length_t left, length;
	const unsigned char *ptr;
	risp_command_t cmd;
	unsigned char style;
	risp_int_t value;
	int cont = 1;
	
	// risp_int_t should be a 64-bit long.
	assert(sizeof(risp_int_t) == 8);
	
	// we also do some bit manipulation of the command, and assume that it is 1 byte only.
	assert(sizeof(risp_command_t) == 1);
	
	// callback function prototypes.
	void (*func_nul)(void *base) = NULL;
	void (*func_int)(void *base, const risp_int_t value) = NULL;
	void (*func_str)(void *base, const risp_length_t length, const void *data) = NULL;
	
 	assert(risp != NULL);
	
	// why run this function if there is no data?
 	assert(len > 0);
 	assert(data != NULL);
	
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
				if (func_nul) { (*func_nul)(base); }
				else { risp->commands[cmd].set = 1; }
				ptr++;
				left--;
				break;
				
			case 2:
				// 64 to 95		1 byte param
				if (left > 1) {
					value = (unsigned char) ptr[1];
					func_int = risp->commands[cmd].handler;
					if (func_int) {
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
				// 96 to 127		4 byte param
				if (left > 4) {
					value = ntohl((unsigned long) *(ptr+1));
					func_int = risp->commands[cmd].handler;
					if (func_int) {
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
				
			case 4:
				// 128 to 159		8 byte param
				if (left > 8) {
					value = ntohll((unsigned long long) *(ptr+1));
					func_int = risp->commands[cmd].handler;
					if (func_int) {
						(*func_int)(base, value);
					}
					else {
						risp->commands[cmd].set = 1;
						risp->commands[cmd].value = value; 
					}
					ptr += 9;
					left -= 9;
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
								risp->commands[cmd].buffer = realloc(risp->commands[cmd].buffer, length+1);
							}
							memcpy(risp->commands[cmd].buffer, ptr+2, length);
							risp->commands[cmd].buffer[length] = 0;
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
					length = ntohs((unsigned short int) *(ptr+1));
					if (left > 2 + length) {
						func_str = risp->commands[cmd].handler;
						if (func_str)      (*func_str)(base, length, ptr+3);
						else {
							if (risp->commands[cmd].max < length) {
								risp->commands[cmd].max = length;
								risp->commands[cmd].buffer = realloc(risp->commands[cmd].buffer, length+1);
							}
							memcpy(risp->commands[cmd].buffer, ptr+3, length);
							risp->commands[cmd].buffer[length] = 0;
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
					length = ntohl((unsigned short int) *(ptr+1));
					if (left > 4 + length) {
						func_str = risp->commands[cmd].handler;
						if (func_str) 	   (*func_str)(base, length, ptr+5);
						else {
							if (risp->commands[cmd].max < length) {
								risp->commands[cmd].max = length;
								risp->commands[cmd].buffer = realloc(risp->commands[cmd].buffer, length+1);
							}
							memcpy(risp->commands[cmd].buffer, ptr+5, length);
							risp->commands[cmd].buffer[length] = 0;
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
	
	assert((len - left) >= 0);	

	// looks like we are returning the number of bytes processed, rather than the amount left in the buffer.
	return(len - left);
}


// return 0 if not set, 1 if it is.
int risp_isset(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(risp->commands[command].handler == NULL);
	return(risp->commands[command].set);
}


risp_int_t risp_getvalue(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(command >= 64 && command <= 159);
	assert(risp->commands[command].set != 0);
	assert(risp->commands[command].handler == NULL);
	return(risp->commands[command].value);
}

risp_length_t risp_getlength(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(command >= 160 && command <= 255);
	if (command >= 160 && command <= 255) {
		assert(risp->commands[command].set != 0);
		assert(risp->commands[command].handler == NULL);
		assert(risp->commands[command].length <= risp->commands[command].max);
		return(risp->commands[command].length);
	}
	else {
		// if you get to this point, developer error.
		assert(0);
		return(0);
	}
}


risp_data_t * risp_getdata(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(command >= 160 && command <= 255);
	assert(risp->commands[command].set != 0);
	assert(risp->commands[command].handler == NULL);
	assert(risp->commands[command].length <= risp->commands[command].max);
	assert(risp->commands[command].max > 0);
	assert(risp->commands[command].buffer);
	return(risp->commands[command].buffer);
}

char * risp_getstring(risp_t *risp, risp_command_t command)
{
	assert(risp);
	assert(command >= 160 && command <= 255);
	assert(risp->commands[command].handler == NULL);
	assert(risp->commands[command].set != 0);
	assert(risp->commands[command].max > 0);
	assert(risp->commands[command].value == 0);
	assert(risp->commands[command].length <= risp->commands[command].max);
	assert(risp->commands[command].buffer);
	assert(risp->commands[command].buffer[risp->commands[command].length] == 0);
	return(risp->commands[command].buffer);
}




