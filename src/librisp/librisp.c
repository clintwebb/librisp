//-----------------------------------------------------------------------------
/*
    librisp
    see risp.h for details.
    Copyright (C) 2015  Clinton Webb

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


*/
//-----------------------------------------------------------------------------



#include "risp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>


#include <stdio.h>

#if (RISP_VERSION != 0x00040200)
#error "Incorrect header version.  code and header versions must match."
#endif

// A Random number that is applied to every risp_t structure to verify that the pointer is actually pointing to an initiated object.
// NOTE: This identifier should change when functional changes are made to the structure.
#define RISP_STRUCT_VERIFIER 648564785


typedef struct {
	void *callback;
} risp_handler_t;


typedef struct {
	long long verifier;
	risp_handler_t commands[RISP_MAX_USER_CMD+1];
	void * invalid_callback;
} risp_t;






// These helper functions should not be needed now.
// // 'functions' to convert 64-bit longs between host-byte-order and network-byte-order.
// #define htonll(x) ((1==htonl(1)) ? (x) : ((unsigned long long)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
// #define ntohll(x) ((1==ntohl(1)) ? (x) : ((unsigned long long)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))


//--------------------------------------------------------------------------------------------------
// Return the library version number (run-time rather than compile-time).  When ensuring that the 
// right library version is installed, need to use this function rather than the version in the 
// library header.  This is because the header only gives the version of the library that this was 
// compiled on, not what it is running on.
long long risp_version(void)
{
	return(RISP_VERSION);
}



//--------------------------------------------------------------------------------------------------
// Initialise everything we need to initialise.   This will return a pointer to a risp_t structure 
// that has been allocated and initialised.  
RISP risp_init(void)
{
	risp_t *r;

	// Assume some sane type sizes.    
	assert(sizeof(short) == 2);
	assert(sizeof(int) == 4);
	// (long) by itself could be either 4 or 8, depending on if it is running on 32-bit or 64-bit system.
	assert(sizeof(long long) == 8);

	// risp_int_t should be 64-bit long.
	assert(sizeof(risp_int_t) == 8);

	// we also do some bit manipulation of the command, and assume that it is 2 bytes only.
	assert(sizeof(risp_command_t) == 2);

	// The 'commands' are expected to be a 16-bit unsigned integer.
	assert(sizeof(risp_command_t) == 2);
	assert(RISP_MAX_USER_CMD <= (256*256));

	// allocate memory for the main struct.
	r = (risp_t *) malloc(sizeof(risp_t));
	r->verifier = RISP_STRUCT_VERIFIER;

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
	
	assert(r->verifier == RISP_STRUCT_VERIFIER);
	return(r);
}



//--------------------------------------------------------------------------------------------------
// Clean up the structure that were created by the library.  
void risp_shutdown(RISP r)
{
	// if a NULL was passed in, then the developer has probably made a mistake.
	assert(r != NULL);
	if (r != NULL) {
		risp_t *risp = (risp_t *) r;

		// Verify that the object referenced by the pointer appears to be a valid RISP structure.
		assert(risp->verifier == RISP_STRUCT_VERIFIER);
		if (risp->verifier != RISP_STRUCT_VERIFIER) {
			return;
		}
		
		int i;
		for (i=0; i<RISP_MAX_USER_CMD; i++) {
			risp->commands[i].callback = NULL;
		}
		
		// we allocated the space, so we need to free it.
		free(risp);	risp = NULL;
	}
}


//--------------------------------------------------------------------------------------------------
// The invalid callback will be called if a command is received that does not have a callback 
// listed.  This is to assist with handling issues where unexpected commands are received.  Normally 
// they should be ignored, but might want to log it or suggest and update, etc.
// 
// Passing in a NULL callback essentially disables it.
void risp_add_invalid(RISP r, void *callback)
{
	assert(r);
	
	if (r) {
		risp_t *risp = (risp_t *) r;
		
		assert(risp->verifier == RISP_STRUCT_VERIFIER);
		if (risp->verifier == RISP_STRUCT_VERIFIER) {
			risp->invalid_callback = callback;
		}
 	}
}


//-----------------------------------------------------------------------------
// Add a command to our tables.  Since we are using an array of function 
// pointers, risp does not know definitively that the function specified 
// expects the correct parameters.  If the callback function is not the correct 
// type for the command-style, then it will generally end up with a segfault.
void risp_add_command(RISP r, risp_command_t command, void *callback) 
{
// 	printf("add_cmd: command:%u, max:%lu\n", command, RISP_MAX_USER_CMD);
	
	assert(r);
	assert(command >= 0);
	assert(command < RISP_MAX_USER_CMD);
	assert(callback != NULL);
	
	if (r) {
		risp_t *risp = (risp_t *) r;
		
		assert(risp->verifier == RISP_STRUCT_VERIFIER);
		if (risp->verifier == RISP_STRUCT_VERIFIER) {
			assert(risp->commands[command].callback == NULL);
			risp->commands[command].callback = callback;
		}
	}
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
// 		fprintf(stderr, "%s\n", buffer);
	}
}



//--------------------------------------------------------------------------------------------------
// Process all the commands in the data buffer, returning the number of bytes processed.  If we dont 
// have enough data to complete the operation, then the calling function can then figure out what to 
// do with it.
risp_length_t risp_process(RISP r, void *base, risp_length_t len, const void *data)
{
	risp_length_t processed = 0;
	
#ifndef NDEBUG
	static int itcount = 0;	// iteration counter for the debug output.
	itcount ++;
// 	fprintf(stderr, "RISP Process: itcount:%d, len=%ld\n", itcount, len);
#endif
	
	// callback function prototypes.
	void (*func_nul)(void *base) = NULL;
	void (*func_int)(void *base, const risp_int_t value) = NULL;
	void (*func_str)(void *base, const risp_length_t length, const void *data) = NULL;

	risp_length_t left = len;
	const unsigned char *ptr = (char *) data;
	
	assert(r);
	if (r) {
		risp_t *risp = (risp_t *) r;
		
		assert(risp->verifier == RISP_STRUCT_VERIFIER);
		if (risp->verifier == RISP_STRUCT_VERIFIER) {
			
			
			// why run this function if there is no data?
			assert(len > 0);
			assert(data != NULL);
			

			// sanity check.
			assert(sizeof(risp_command_t) == 2);
			
			// Need at least 2 bytes for the command.
			int cont = 1;
			while(cont != 0 && left >= sizeof(risp_command_t)) {

				assert(len == (left + processed));
		// 		fprintf(stderr, "Buffer Length: %ld\n", left);
		// 		log_data("IN: ", (unsigned char*) ptr, left);
				
				// Each command in the protocol is made up of two parts, the style bitmap, and the 
				// command id.  Together they make up a command in the protocol, but since we will be 
				// seperating them anyway, we might as well pull them out together.

				risp_command_t cmd = ptr[0];	// add the first byte
				cmd <<= 8;	// shift it into position.
				cmd |= ptr[1];
				
				ptr += 2;
				
				// There are certain ranges that are specifically set aside for commands that have no parameters.
				// These are: 
				// 		No Parameters - 0x7000 to 0x7fff          0 111 xxxx xxxx
				// 		No Parameters - 0xc000 to 0xffff          1 1xx xxxx xxxx
				// We can therefore check for specific bits in the style.

				// Note that 0x7 and 0xC overlap, but thats ok, because the overlap is still within either range.
				if ((cmd >= 0x7000 && cmd <= 0x7fff) || (cmd >= 0xc000)) {
					
					// there is no parameters, so we call the callback routine with just the command.
					func_nul = risp->commands[cmd].callback;
					if (func_nul) { (*func_nul)(base); }
					assert(sizeof(risp_command_t) == 2);
					risp_length_t completed = sizeof(risp_command_t);
		// 			fprintf(stderr, "Completed: %ld\n", completed);
					left -= completed;
					processed += completed;
					// dont need to increase the ptr, because there was no parameters.
				}
				else {
					
// 					fprintf(stderr, "RISP: cmd=%llx\n", cmd);
					
					// make sure we haven't made a mistake determining the non-param ranges.
					assert((cmd < 0x7000 || cmd > 0x7fff) && cmd < 0xc000);
					
					// Since the command was not within the no-param range, then we need to parse the integer size.
					short int_bits = (cmd & 0x7000) >> 12;
					short int_len = 1 << int_bits;
// 					fprintf(stderr, "RISP: int_bits=%d\n", int_bits);
//			 		fprintf(stderr, "RISP: int_len=%d\n", int_len);

					if (left < (sizeof(risp_command_t) + int_len)) {
						// there is not enough data in the buffer to process.  so we need to exit the loop and 
						// not process any more.
						cont = 0;
					}
					else {
						
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
						
						if ((cmd & 0x8000) == 0) {
							// this command is NOT a string, so we have all that we need.
			// 				fprintf(stderr, "RISP. command is INTEGER(len:%d)\n", int_len);
							func_int = risp->commands[cmd].callback;
							if (func_int) { (*func_int)(base, intvalue); }
							risp_length_t completed = (sizeof(risp_command_t) + int_len);
			// 				fprintf(stderr, "Completed: %ld\n", completed);
							left -= completed;
							processed += completed;
							// dont need to increase the ptr, because that was done when we were reading in the integer.
						}
						else {
							// this command is a string, so we also need to get the rest of it.
			// 				fprintf(stderr, "RISP. command is STRING(len:%d,%ld)\n", int_len, intvalue);
							
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
			// 					fprintf(stderr, "Completed: %ld\n", completed);
								left -= completed;
								processed += completed;
								assert(left >= 0);
							}
						}
					}
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


//--------------------------------------------------------------------------------------------------
// Peek in the data buffer to determine how much data we need.   This command will tell you how many 
// bytes it needs for the next (and only the next) complete command in the buffer.  Note that it may 
// not have all the data it needs, so it may return how much data it needs to get to the next step.
risp_length_t risp_needs(risp_length_t len, const void *data)
{
	risp_length_t needs = 0;
	
	// risp_int_t should be 64-bit long.
	assert(sizeof(risp_int_t) == 8);
	
	// we also do some bit manipulation of the command, and assume that it is 2 bytes only.
	assert(sizeof(risp_command_t) == 2);
	
	const unsigned char *ptr = (char *) data;
	
	assert(data != NULL);
	assert(len >= 0);
	
	if (len <= sizeof(risp_command_t)) {
		needs = sizeof(risp_command_t);
	}
	else {
		
		// Each command in the protocol is made up of two parts, the style bitmap, and the 
		// command id.  Together they make up a command in the protocol, but since we will be 
		// seperating them anyway, we might as well pull them out together.

		risp_command_t cmd = ptr[0];	// add the first byte
		cmd <<= 8;	// shift it into position.
		cmd |= ptr[1];
		
		ptr += 2;

		// There are certain ranges that are specifically set aside for commands that have no parameters.
		// These are: 
		// 		No Parameters - 0x7000 to 0x7fff          0 111 xxxx xxxx
		// 		No Parameters - 0xc000 to 0xffff          1 1xx xxxx xxxx
		// We can therefore check for specific bits in the style.

		// Note that 0x7 and 0xC overlap, but thats ok, because the overlap is still within either range.
		if ((cmd >= 0x7000 && cmd <= 0x7fff) || (cmd >= 0xc000)) {
			needs = sizeof(risp_command_t);
		}
		else {
		
			// make sure we haven't made a mistake determining the non-param ranges.
			assert((cmd < 0x7000 || cmd > 0x7fff) && cmd < 0xc000);

			// Since the command was not within the no-param range, then we need to parse the integer size.
			short int_bits = (cmd & 0x7000) >> 12;
			short int_len = 1 << int_bits;

			// We now know how many bytes are needed for the integer.
			needs = sizeof(risp_command_t) + int_len;

			// Now we need to check if this command has a string that follows or not.  If not, then 
			// we already know all we need.  If it is a string, we will need to get the integer value, 
			// because that will tell us how long the string is.

			if ((cmd & 0x8000) != 0) {
				// this command is a string.

				// this code only handles values up to risp_int_t size.
				assert(int_len <= sizeof(risp_int_t));
				// TODO: trim the int_len so that it will fit..
								
				// we know how big the integer is, we need to actually get it.
				risp_int_t intvalue = 0;
				register short counter;
				for (counter=0; counter < int_len; counter++) {
					
					// shift the value to the left.
					// not necessary for the first iteration, but it is cheaper than checking for it.
					intvalue <<= 8;
					
					intvalue |= *ptr;
					ptr ++;
				}
						
				needs = sizeof(risp_command_t) + int_len + intvalue;
			}
		}
	}

	assert(needs >= sizeof(risp_command_t));
	
	// return the number of bytes needed to process the next command (including what we already have);
	return(needs);
}





// to assist with knowing how much space a command will need to be reserved for a buffer, this 
// function will tell you how many bytes the command will use.
risp_length_t risp_command_length(risp_command_t command, risp_length_t dataLength)
{
	risp_length_t length = 0;

	assert(dataLength >= 0);
// 	fprintf(stderr, "risp_command_length: command=%X\n", command);

	// start with the size of the command id.
	length = sizeof(risp_command_t);
	assert(length == 2);
// 	fprintf(stderr, "risp_command_length: length=%d\n", length);

	
	if ((command >= 0x7000 && command <= 0x7fff) || (command >= 0xc000)) {
		// command specifically has no parameters.
// 		fprintf(stderr, "risp_command_length: no parameters\n");
		
		assert(length == 2);
		assert(dataLength <= 0);
	}
	else {
	
		// the style part of the command is the highest 4-bits.
		unsigned char style = (command >> (16-4));
// 		fprintf(stderr, "risp_command_length: style=%X\n", style);
		
		
		// the lowest 3 bits are the length (2 to the power of) of the integer part.
		unsigned char int_bits = (style & 0x7);
		assert(int_bits < 8);
		unsigned char int_len = 1 << int_bits;
		length += int_len;
// 		fprintf(stderr, "risp_command_length: int_bits=%X\n", int_bits);
// 		fprintf(stderr, "risp_command_length: int_len=%d\n", int_len);
// 		fprintf(stderr, "risp_command_length: length=%d\n", length);
		
		// if there was an integer part, AND it is also a string, then we need to add the dataLength part. 
		if (int_len > 0 && (style & 0x8)) {
// 			fprintf(stderr, "risp_command_length: is a string:%d\n", dataLength);

			length += dataLength;
		}
// 		fprintf(stderr, "risp_command_length: length=%d\n", length);		
	}
	
	assert(length >= sizeof(risp_command_t));
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

	// first we need to make sure that this command really is within neither the integer or string ranges.
	if ((command >= 0x7000 && command <= 0x7fff) || command >= 0xc000) {
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
	if (command < 0x7000) {
		/// command expects an integer parameter.

		// get the length out of the command-id.
		short int int_bits = (command & 0x7000) >> 12;
		short int int_len = 1 << int_bits;
		
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
	if (command >= 0x8000 && command <= 0xbfff) {
		
		/// command expects an integer parameter, followed by data of that length.

		// get the length out of the command-id.
		short int int_bits = (command & 0x7000) >> 12;
		short int int_len = 1 << int_bits;
		
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





