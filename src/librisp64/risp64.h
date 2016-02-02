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

#ifndef __LIBRISP64_H
#define __LIBRISP64_H


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


#define RISP_VERSION 0x00030000
#define RISP_VERSION_NAME "v3.00.00"

// the RISP commands are 16-bit integers.
#define RISP_MAX_USER_CMD    (2^16)

///////////////////////////////////////////
// create the types that we will be using.

typedef uint16_t      risp_command_t;
typedef int_least64_t risp_length_t;
typedef int_least64_t risp_int_t;
typedef unsigned char risp_data_t;	// will be used as a pointer.


typedef struct {
	void * commands[RISP_MAX_USER_CMD];
	char created_internally;
} risp_t;


///////////////////////////////////////////
// declare the public functions.

// init and shutdown.
risp_t *risp_init(risp_t *risp);
risp_t *risp_shutdown(risp_t *risp);



// setup of callback commands
void risp_add_command(risp_t *risp, risp_command_t command, void *callback);

// providing data that needs to be processed and sent to the callback commands.  
// Will return the number of bytes that were processed.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t length, const void *data);


#endif
