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


//--------------------------------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to a risp_t structure 
// that has been allocated and initialised.  If the parameter is NULL, it will allocate space.  If a 
// pointer param is provided, it will initialize that space instead.
risp_t *risp_init(risp_t *risp)
{
	risp_t *r;

	// Assume some sane type sizes.    
	assert(sizeof(int) == 4);
	assert(sizeof(short) == 2);
	assert(sizeof(long) == sizeof(int));
	assert(sizeof(long long) == 8);
	
	// The 'commands' are expected to be a 16-bit unsigned integer.
	assert(sizeof(risp_command_t) == 2);
	assert(RISP_MAX_USER_CMD <= (256*256));

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
		register short i;
		for (i=0; i<RISP_MAX_USER_CMD; i++) {
			r->commands[i] = NULL;
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
		risp->commands[i] = NULL;
	}
	
	assert(risp->created_internally == 1 | risp->created_internally == 0);
	if (risp->created_internally == 0) {
		// risp structure was not created internally, caller must take care of it.
		return(risp);
	}
	else {
		// we allocated the space, so we need to free it.
		free(risp);	risp = NULL;
		return(NULL);
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
	
	assert(risp->commands[command] == NULL);
	risp->commands[command] = callback;
}


//--------------------------------------------------------------------------------------------------
// Process all the commands in the data buffer, returning the number of bytes processed.  If we dont 
// have enough data to complete the operation, then the calling function can then figure out what to 
// do with it.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t len, const void *data)
{
	// risp_int_t should be 64-bit long.
	assert(sizeof(risp_int_t) == 8);
	
	// we also do some bit manipulation of the command, and assume that it is 2 bytes only.
	assert(sizeof(risp_command_t) == 2);
	
	// callback function prototypes.
	void (*func_nul)(void *base) = NULL;
	void (*func_int)(void *base, const risp_int_t value) = NULL;
	void (*func_str)(void *base, const risp_length_t length, const void *data) = NULL;
	
 	assert(risp != NULL);
	
	// why run this function if there is no data?
 	assert(len > 0);
 	assert(data != NULL);
	
	risp_length_t left = len;
	const unsigned char *ptr = (char *) data;

	// Need at least 2 bytes for the command.
	int cont = 1;
	while(cont != 0 && left >= 2) {

		// Each command in the protocol is made up of two parts, the style bitmap, and the 
		// command id.  Together they make up a command in the protocol, but since we will be 
		// seperating them anyway, we might as well pull them out together.

		// the first byte also contains the style bits, so we will keep that first.
		unsigned char style = *ptr;
		ptr ++;
		
		// add the style part we already got to the first byte in the command, and then add the 
		// second byte.
		risp_command_t cmd = (((short)style) << 8) | *ptr;
		ptr ++;

		// get rid of the bits from style we dont want when checking it.  Note that the style bits 
		// make up the first 5 bits.
		style = style >> (8-5);

		// get the length of the integer part of our command (if there is one).
		short int_len = style & 0xff;
		
		if (int_len == 0) {
			func_nul = risp->commands[cmd];
			if (func_nul) { (*func_nul)(base); }
			left -= sizeof(risp_command_t);
			// dont need to increase the ptr, because there was no parameters.
		}
		else if (left >= (sizeof(risp_command_t) + int_len)) {
			
			// this code only handles values up to risp_int_t size.
			assert(int_len <= sizeof(risp_int_t));
			// TODO: trim the int_len so that it will fit..
			
			risp_int_t intvalue = 0;
			register short counter;
			for (counter=0; counter < int_len; counter++) {
				
				// shift the value to the left.
				// not necessary for the first iteration, but it is cheaper than checking for it.
				intvalue <<= 8;
				
				intvalue |= *ptr;
				ptr ++;
			}
			
			// we have the first param.  Not sure yet if it is an integer parameter, or the length 
			// of the string that will follow.  We will check the 'style' bitmap for that.
			
			if (style & 0x10 != 0x10) {
				// this command is NOT a string, so we have all that we need.
				func_int = risp->commands[cmd];
				if (func_int) { (*func_int)(base, intvalue); }
				left -= (sizeof(risp_command_t) + int_len);
				// dont need to increase the ptr, because that was done when we were reading in the integer.
			}
			else {
				// this command is a string, so we also need to get the rest of it.
				
				// first, we need to make sure we have enough data.
				if (left < (sizeof(risp_command_t) + int_len + intvalue)) {
					// have not received all the data yet.  a 'cont' of zero will indicate not to continue the loop.
					cont = 0;
				}
				else {
					func_str = risp->commands[cmd];
					if (func_str) (*func_str)(base, intvalue, ptr);
					ptr += intvalue;
					left -= (sizeof(risp_command_t) + int_len + intvalue);
				}
			}
		}
	}	
	
	assert((len - left) >= 0);	

	// looks like we are returning the number of bytes processed, rather than the amount left in the buffer.
	return(len - left);
}



// to assist with knowing how much space a command will need to be reserved for a buffer, this 
// function will tell you how many bytes the command will use.
risp_length_t risp_command_length(risp_command_t command, risp_length_t dataLength)
{
	risp_length_t length = 0;

	assert(dataLength >= 0);

	unsigned char style = (command >> (8+(8-5)));
	
	// start with the size of the command id.
	length = 2;
	
	// the lowest 4 bits are the length of the integer part.
	unsigned int int_len = (style & 0xFF);
	length += int_len;
	
	// if there was an integer part, AND it is also a string, then we need to add the dataLength part. 
	if (int_len > 0 && (style & 0x100)) {
		length += dataLength;
	}
	
	assert(length >= 0);
	return(length);
}


// add an int in network-byte-order (big endian).
void network_int(void *buffer, risp_int_t value, short int_len) 
{
	assert(buffer);
	assert(int_len > 0);
	
	short added = 0;
	unsigned char *ptr = buffer;

	int i, skip;
	for (i=0,skip=int_len-1; i<(int_len-1); i++,skip--) {
		assert(skip > 0); 
		*ptr = (unsigned char) ((value >> (8*skip)) & 0xf); 
		ptr++; added++;
	}
	
	// now add the final byte
	*ptr = (unsigned char) (value & 0xf);
	ptr++; added++;
	
	assert(added == int_len);
}




// Returns how many bytes it added to the buffer.  The buffer must be big enough to accept the command.
risp_length_t risp_addbuf_noparam(void *buffer, risp_command_t command)
{
	risp_length_t added = 0;

	assert(sizeof(risp_command_t) == 2);
	
	assert(buffer);
	unsigned char *ptr = buffer;

	unsigned char style = command >> (8+(8-5));

	// first we need to make sure that this command really is an integer command, and not a string.
	if ((style & 0xf) == 0) {

		network_int(ptr, command, sizeof(risp_command_t));
		ptr += sizeof(risp_command_t);
		added += sizeof(risp_command_t);
		
		assert(added == sizeof(risp_command_t));
	}
	
	assert(added >= 0);
	return(added);
}

risp_length_t risp_addbuf_int(void *buffer, risp_command_t command, risp_int_t value)
{
	risp_length_t added = 0;
	
	assert(buffer);
	unsigned char *ptr = buffer;

	unsigned char style = command >> (8+(8-5));
	
	// first we need to make sure that this command really is an integer command, and not a string.
	if (((style & 0x10) == 0) && ((style & 0xf) != 0)) {
		/// command expects an integer parameter.

		int int_len = style & 0xf;
		assert(int_len > 0);
		
		// the max size we can handle is the size of the 'value' param to this function... so we 
		// will reject anything larger than that.
		if (int_len > sizeof(value)) {
			assert(added == 0);

			// the developer probably did something wrong if this fires.
			assert(0);
		}
		else {
			network_int(ptr, command, sizeof(risp_command_t));
			ptr += sizeof(risp_command_t);
			added += sizeof(risp_command_t);

			network_int(ptr, value, int_len);
			ptr += int_len;
			added += int_len;
			
			assert(added == (sizeof(risp_command_t)+int_len));
		}
	}
	
	assert(added >= 0);
	return(added);
}


risp_length_t risp_addbuf_str(void *buffer, risp_command_t command, risp_length_t length, void *data)
{
	risp_length_t added = 0;
	
	assert(buffer);
	assert(command != 0);
	assert(length >= 0);
	assert(data);
	
	unsigned char *ptr = buffer;

	unsigned char style = command >> (8+(8-5));
	
	// first we need to make sure that this command really is an integer command, and not a string.
	if (((style & 0x10) == 1) && ((style & 0xf) != 0)) {
		/// command expects an integer parameter, followed by data of that length.

		int int_len = style & 0xf;
		assert(int_len > 0);
		
		// the max size we can handle is the size of the 'value' param to this function... so we 
		// will reject anything larger than that.
		if (int_len > sizeof(length)) {
			assert(added == 0);

			// the developer probably did something wrong if this fires.
			assert(0);
		}
		else {
			network_int(ptr, command, sizeof(risp_command_t));
			ptr += sizeof(risp_command_t);
			added += sizeof(risp_command_t);

			network_int(ptr, length, int_len);
			ptr += int_len;
			added += int_len;
	
			if (length > 0) {
				memcpy(ptr, data, length);
				added += length;
			}
			
			assert(added == (sizeof(risp_command_t)+int_len+length));
		}
	}
	
	assert(added >= 0);
	return(added);
}





