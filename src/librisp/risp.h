//-----------------------------------------------------------------------------
//   librisp
//   -------
//   library to handle the low-level operations of a  Reduced Instruction Set 
//   Protocol.
//
//   Copyright (C) 2008  Hyper-Active Sytems.
//   Copyright (C) 2015  Clinton Webb
//   Copyright (C) 2016  Clinton Webb

/*
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser Public License for more details.

    You should have received a copy of the GNU Lesser Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
//-----------------------------------------------------------------------------

#ifndef __LIBRISP_H
#define __LIBRISP_H


/*
 * Version 4.0
 * 
 * Major (and hopefully final) change to the base protocol.   The change is intended to remove a 
 * significant range of ID's that will never be used in reality (5-byte integers for example), and 
 * instead provide more of the ranges that people will be using.  The 4-bits that indicate the byte 
 * length of the integer that follows is being changed to a 3-bit multiple (2 to the power of).
 *
 *   1 byte integer - 0x0000 to 0x0fff         0 000 xxxx xxxx
 *   2 byte integer - 0x1000 to 0x1fff         0 001 xxxx xxxx
 *   4 byte integer - 0x2000 to 0x2fff         0 010 xxxx xxxx
 *   8 byte integer - 0x3000 to 0x3fff         0 011 xxxx xxxx
 *   16 byte integer - 0x4000 to 0x4fff        0 100 xxxx xxxx
 *   32 byte integer - 0x5000 to 0x5fff        0 101 xxxx xxxx
 *   64 byte integer - 0x6000 to 0x6fff        0 110 xxxx xxxx
 *   No Parameters - 0x7000 to 0x7fff          0 111 xxxx xxxx
 *   1 byte-length string - 0x8000 to 0x8fff   1 000 xxxx xxxx
 *   2 byte-length string - 0x9000 to 0x9fff   1 001 xxxx xxxx
 *   4 byte-length string - 0xa000 to 0xafff   1 010 xxxx xxxx
 *   8 byte-length string - 0xb000 to 0xbfff   1 011 xxxx xxxx
 *   No Parameters - 0xc000 to 0xffff          1 1xx xxxx xxxx
 *
 *
*/

/*
 * Version 3.0
 *
 * Major change to the base protocol mappings to support 64-bit data, and restructure to provide
 * more large-string parameters.
 *
 * Removed the functionality to store data within the library.  All operations should be handled
 * externally.  We may introduce this feature, but limit it so that it only saves the data for
 * entries that have been specifically set aside for it.
*/

/*
 * Version 2.0
 *
 * Version 1.x did not buffer anything.  Instead it only supported callbacks. With this version, you
 * only need to set a callback for commands that require an action, otherwise the content of the
 * commands that do not have callbacks will be stored and retrieved when needed.   The retreival can
 * be done in a macro, which means that it can be optimised for faster access (normally just a
 * pointer redirection).
*/

/*
 * Version 1.0
*/

#include <stdint.h>


#define RISP_VERSION 0x00040200
#define RISP_VERSION_NAME "v4.02.00"

// the RISP commands are 16-bit integers.
#define RISP_MAX_USER_CMD    (0xffff)







///////////////////////////////////////////
// create the types that we will be using.

typedef uint16_t      risp_command_t;
typedef int_least64_t risp_length_t;
typedef int_least64_t risp_int_t;
typedef unsigned char risp_data_t;	// will be used as a pointer.


///////////////////////////////////////////
// RISP instance handle.   
typedef void * RISP;



///////////////////////////////////////////
// declare the public functions.

// init and shutdown.
RISP risp_init(void);
void risp_shutdown(RISP risp);

// Return the library version number (run-time rather than compile-time)
long long risp_version(void);

// Setup a callback function to be called when an unexpected command is received.
void risp_add_invalid(RISP risp, void *callback);

// setup of callback commands
void risp_add_command(RISP risp, risp_command_t command, void *callback);

// providing data that needs to be processed and sent to the callback commands.
// Will return the number of bytes that were processed.
risp_length_t risp_process(RISP risp, void *base, risp_length_t length, const void *data);


// The buffer functions will assist with adding a command to a buffer that is provided.
risp_length_t risp_addbuf_noparam(void *buffer, risp_command_t command);
risp_length_t risp_addbuf_int(void *buffer, risp_command_t command, risp_int_t value);
risp_length_t risp_addbuf_str(void *buffer, risp_command_t command, risp_length_t length, void *data);


// to assist with knowing how much space a command will need to be reserved for a buffer, this
// function will tell you how many bytes the command will use.
risp_length_t risp_command_length(risp_command_t command, risp_length_t length);

// Peek in the data buffer to determine how much data we need.   This command will tell you how many 
// bytes it needs for the next (and only the next) complete command in the buffer.  Note that it may 
// not have all the data it needs, so it may return how much data it needs to get to the next step.
risp_length_t risp_needs(risp_length_t len, const void *data);


#endif
