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


#include <stdio.h>

#if (RISP_VERSION != 0x00030002)
#error "Incorrect header version.  code and header versions must match."
#endif






// These helper functions should not be needed now.
// // 'functions' to convert 64-bit longs between host-byte-order and network-byte-order.
// #define htonll(x) ((1==htonl(1)) ? (x) : ((unsigned long long)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
// #define ntohll(x) ((1==ntohl(1)) ? (x) : ((unsigned long long)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))


//--------------------------------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to a risp_t structure 
// that has been allocated and initialised.  If the parameter is NULL, it will allocate space.  If a 
// pointer param is provided, it will initialize that space instead.
risp_t *risp_init(risp_t *risp)
{
	risp_t *r;

	// Assume some sane type sizes.    
	assert(sizeof(short) == 2);
	assert(sizeof(int) == 4);
	// (long) by itself could be either 4 or 8, depending on if it is running on 32-bit or 64-bit system.
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
		register unsigned short i;
		for (i=0; i<RISP_MAX_USER_CMD; i++) {
			r->commands[i].callback = NULL;
		}

		// Set the 'invalid' callback to NULL.,  This can be set using risp_add_invalid() function.
		r->invalid_callback = NULL;
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
		risp->commands[i].callback = NULL;
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


//--------------------------------------------------------------------------------------------------
// The invalid callback will be called if a command is received that does not have a callback 
// listed.  This is to assist with handling issues where unexpected commands are received.  Normally 
// they should be ignored, but might want to log it or suggest and update, etc.
// 
// Passing in a NULL callback essentially disables it.
void risp_add_invalid(risp_t *risp, void *callback)
{
	assert(risp);
	risp->invalid_callback = callback;
}


//-----------------------------------------------------------------------------
// Add a command to our tables.  Since we are using an array of function 
// pointers, risp does not know definitively that the function specified 
// expects the correct parameters.  If the callback function is not the correct 
// type for the command-style, then it will generally end up with a segfault.
void risp_add_command(risp_t *risp, risp_command_t command, void *callback) 
{
// 	printf("add_cmd: command:%u, max:%lu\n", command, RISP_MAX_USER_CMD);
	
	assert(risp != NULL);
	assert(command >= 0);
	assert(command < RISP_MAX_USER_CMD);
	assert(callback != NULL);
	
	assert(risp->commands[command].callback == NULL);
	risp->commands[command].callback = callback;
}


static void log_data(char *tag, unsigned char *data, int length)
{
	int i;
	int col;
	char buffer[512];	// line buffer.
	int len;  			// buffer length;
	int start;
	
	assert(tag);
	assert(data);
	assert(length > 0);

	i = 0;
	while (i < length) {

		start = i;
		
		// first put the tag in the buffer.
		strncpy(buffer, tag, sizeof(buffer));
		len = strlen(tag);
		
		// now put the line count.
		len += sprintf(buffer+len, "%04X: ", i);
		
		// now display the columns of text.
		for (col=0; col<16; col++) {
			if (i < length && col==7) {
				len += sprintf(buffer+len, "%02x-", data[i]);
			}
			else if (i < length) {
				len += sprintf(buffer+len, "%02x ", data[i]);
			}
			else {
				len += sprintf(buffer+len, "   ");
			}
			
			i++;
		}
		
		// add a seperator
		len += sprintf(buffer+len, ": ");
		
		// now we display the plain text.
		assert(start >= 0);
		for (col=0; col<16; col++) {
			if (start < length) {
				if (isprint(data[start])) {
					len += sprintf(buffer+len, "%c", data[start]);
				}
				else {
					len += sprintf(buffer+len, ".");
				}
			}
			else {
				len += sprintf(buffer+len, " ");
			}
			
			start++;
		}

		assert(i == start);
		fprintf(stderr, "%s\n", buffer);
	}
}



//--------------------------------------------------------------------------------------------------
// Process all the commands in the data buffer, returning the number of bytes processed.  If we dont 
// have enough data to complete the operation, then the calling function can then figure out what to 
// do with it.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t len, const void *data)
{
	risp_length_t processed = 0;
	
	static itcount = 0;	// iteration counter for the debug output.
	itcount ++;
// 	fprintf(stderr, "RISP Process: itcount:%d, len=%d\n", itcount, len);
	
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

		assert(len == (left + processed));
		
//  		log_data("IN: ", ptr, left);
		
		// Each command in the protocol is made up of two parts, the style bitmap, and the 
		// command id.  Together they make up a command in the protocol, but since we will be 
		// seperating them anyway, we might as well pull them out together.

		risp_command_t cmd = ptr[0];	// add the first byte
		cmd <<= 8;	// shift it into position.
		cmd |= ptr[1];
		
		ptr += 2;
		
//  		fprintf(stderr, "RISP: Command received: 0x%llx\n", cmd);
		
		// get rid of the bits from style we dont want when checking it.  Note that the style bits 
		// make up the first 5 bits.
		unsigned char style = cmd >> 11;
		
//  		fprintf(stderr, "RISP: Style: 0x%llx\n", style);

		// get the length of the integer part of our command (if there is one), by simply stripping off the string-bit.
		short int_len = style & 0xf;
//  		fprintf(stderr, "RISP: int_len=%d\n", int_len);
		assert(int_len < 16);
		assert(int_len <= 8);	// we cannot handle any integer value greater than 64-bit.
		
		if (int_len == 0) {
			func_nul = risp->commands[cmd].callback;
			if (func_nul) { (*func_nul)(base); }
			assert(sizeof(risp_command_t) == 2);
			risp_length_t completed = sizeof(risp_command_t);
// 			fprintf(stderr, "Completed: %d\n", completed);
			left -= completed;
			processed += completed;
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
			
			if ((style >> 4) == 0) {
				// this command is NOT a string, so we have all that we need.
				fprintf(stderr, "RISP. command is INTEGER(len:%d)\n", int_len);
				func_int = risp->commands[cmd].callback;
				if (func_int) { (*func_int)(base, intvalue); }
				risp_length_t completed = (sizeof(risp_command_t) + int_len);
// 				fprintf(stderr, "Completed: %d\n", completed);
				left -= completed;
				processed += completed;
				// dont need to increase the ptr, because that was done when we were reading in the integer.
			}
			else {
				// this command is a string, so we also need to get the rest of it.
// 				fprintf(stderr, "RISP. command is STRING(len:%d)\n", int_len);
				
				// first, we need to make sure we have enough data.
				if (left < (sizeof(risp_command_t) + int_len + intvalue)) {
					// have not received all the data yet.  a 'cont' of zero will indicate not to continue the loop.
					cont = 0;
				}
				else {
					func_str = risp->commands[cmd].callback;
					if (func_str) (*func_str)(base, intvalue, ptr);
					ptr += intvalue;
					risp_length_t completed = (sizeof(risp_command_t) + int_len + intvalue);
// 					fprintf(stderr, "Completed: %d\n", completed);
					left -= completed;
					processed += completed;
					assert(left >= 0);
				}
			}
		}
	}	

	assert(processed + left == len);
	
	assert(processed >= 0);	
	assert(processed <= len);

	// looks like we are returning the number of bytes processed, rather than the amount left in the buffer.
	return(processed);
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


// add an integer of an arbitrary length (up to 64-bit) in network-byte-order (big endian).
void network_int(unsigned char *buffer, risp_int_t value, short int_len) 
{
	assert(buffer);
	assert(int_len > 0);
	
	short added = 0;

// 	printf("Network Int: value=%llx, len=%d\n", value, int_len);
// 	if (int_len == 2) {
// 		printf("htons: host=%llx, net=%llx\n", value, htons(value));
// 	}
	
	register int i, skip;
	for (i=0,skip=int_len-1; i<(int_len-1); i++,skip--) {
		assert(skip > 0); 
		unsigned char conv = ((value >> (8*skip)) & 0xff);
// 		printf("Adding 0x%X, skip=%d\n", conv, skip);
		buffer[i] = conv; 
		added++;
	}
	
	// now add the final byte
	buffer[i] = (unsigned char) (value & 0xff);
	added++;
	
	assert(added == int_len);
}




// Returns how many bytes it added to the buffer.  The buffer must be big enough to accept the command.
risp_length_t risp_addbuf_noparam(void *buffer, risp_command_t command)
{
	risp_length_t added = 0;

	assert(sizeof(risp_command_t) == 2);
	
	assert(buffer);
	unsigned char *ptr = buffer;

	// first we need to make sure that this command really is an integer command, and not a string.
	if ((command & 0x7800) == 0) {
		network_int(ptr, command, sizeof(risp_command_t));
		ptr += sizeof(risp_command_t);
		added += sizeof(risp_command_t);
		
		assert(added == sizeof(risp_command_t));
	}
	else {
		// a command of an invalid type must have been selected.  Check your Command ID's.  
		// Commands with no params should be in the range of 0x0000 to 0x07ff, and 0x8000 to 0x87ff.
		assert(0);
	}
	
	assert(added > 0);
	return(added);
}

risp_length_t risp_addbuf_int(void *buffer, risp_command_t command, risp_int_t value)
{
	risp_length_t added = 0;
	
	assert(buffer);
	unsigned char *ptr = buffer;

	// this code assumes that the command is a 2-byte (16-bit) value.
	assert(sizeof(risp_command_t) == 2);
	
	// first we need to make sure that this command really is an integer command, and not a string.
	if (((command & 0x8000) == 0) && ((command & 0x7800) != 0)) {
		/// command expects an integer parameter.

		// get the length out of the command-id.
		int int_len = (command & 0x7800) >> 11;
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
	else {
		// a command of an invalid type must have been selected.  
		// integer commands must fall within the range of 0x0800 to 0x47ff.
		assert(0);
	}

	assert(added > 0);
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

	// this code assumes that a command is 2 bytes in length (16-bit).
	assert(sizeof(risp_command_t) == 2);
	
	// first we need to make sure that this command really is a string and not something invalid..
	if (((command & 0x8000) != 0) && ((command & 0x7800) != 0)) {
		
		/// command expects an integer parameter, followed by data of that length.

		int int_len = (command & 0x7800) >> 11;
		assert(int_len > 0);
		
		// the max size we can handle is the size of the 'value' param to this function... so we 
		// will reject anything larger than that.
		if (int_len > sizeof(length)) {
			assert(added == 0);

			// the developer probably did something wrong if this fires.
			assert(0);
		}
		else {
			assert(added == 0);
			assert(sizeof(risp_command_t) == 2);
			assert(ptr);
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
	else {
		// a command of an invalid type must have been selected.
		// Check the command ID's used.
		// string commands must fall within the range of 0x8800 to 0xffff.
		assert(0);
	}

// 	log_data("BUFFER: ",  buffer, added);
	
	
	assert(added > 0);
	return(added);
}





