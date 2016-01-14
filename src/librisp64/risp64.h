//-----------------------------------------------------------------------------
//   librisp
//   -------
//   library to handle the low-level operations of a  Reduced Instruction Set 
//   Protocol.
//
//   Copyright (C) 2008  Hyper-Active Sytems.
//   Copyright (C) 2015  Clinton Webb

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
 * Functions are now provided to apply commands to a buffer.  This was previously handled 
 * externally, but it makes more sense to have it built in.
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


#define RISP_VERSION 0x00030000
#define RISP_VERSION_NAME "v3.00.00"


#define RISP_MAX_USER_CMD    256

///////////////////////////////////////////
// create the types that we will be using.

typedef unsigned char   risp_command_t;
typedef unsigned long   risp_length_t;
typedef long long       risp_int_t;
typedef unsigned char   risp_data_t;


typedef struct {
	struct {
		void          *handler;
		char           set;			// 0 if no data is set, non-zero if it has been.

		// string data
		unsigned int   max;
		unsigned int   length;
		unsigned char *buffer;

		// integer data
		risp_int_t     value;

	} commands[RISP_MAX_USER_CMD];
	char created_internally;
} risp_t;



///////////////////////////////////////////
// declare the public functions.

// init and shutdown.
risp_t *risp_init(risp_t *risp);
risp_t *risp_shutdown(risp_t *risp);

void risp_flush(risp_t *risp);
void risp_clear(risp_t *risp, risp_command_t command);
void risp_clear_all(risp_t *risp);


// setup of callback commands
void risp_add_command(risp_t *risp, risp_command_t command, void *callback);

// providing data that needs to be processed and sent to the callback commands.  
// Will return the number of bytes that were processed.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t length, const void *data);

// these functions should be converted to macro's or inlined somehow to improve efficiency.
int risp_isset(risp_t *risp, risp_command_t command);
risp_int_t risp_getvalue(risp_t *risp, risp_command_t command);
risp_length_t risp_getlength(risp_t *risp, risp_command_t command);
risp_data_t * risp_getdata(risp_t *risp, risp_command_t command);
char * risp_getstring(risp_t *risp, risp_command_t command);
long risp_getlong(risp_t *risp, risp_command_t command);

#endif
