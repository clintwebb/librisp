//-----------------------------------------------------------------------------
//   librisp
//   -------
//   library to handle the low-level operations of a  Reduced Instruction Set 
//   Protocol.
//
//   Copyright, Hyper-Active Sytems, 2008.
//-----------------------------------------------------------------------------

#ifndef __LIBRISP_H
#define __LIBRISP_H


/*
	Version 1.x did not buffer anything.  Instead it only supported callbacks.  
	With this version, you only need to set a callback for commands that 
	require an action, otherwise the content of the commands that do not have 
	callbacks will be stored and retrieved when needed.   The retreival can be 
	done in a macro, which means that it can be optimised for faster access 
	(normally just a pointer redirection).
*/



#define RISP_VERSION 0x00020300
#define RISP_VERSION_NAME "v2.03.00"


#define RISP_MAX_USER_CMD    256

///////////////////////////////////////////
// create the types that we will be using.

typedef unsigned char   risp_command_t;
typedef unsigned int    risp_length_t;
typedef int             risp_int_t;
typedef unsigned char   risp_data_t;


typedef struct {
	struct {
		void *handler;
		char set;
		unsigned int max;
		unsigned int length;
		unsigned char *buffer;
		int value;
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

// providing data that needs to be processed and sent to the callback commands.  Will return the number of bytes that were processed.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t length, const void *data);

// these functions should be converted to macro's or inlined somehow to improve efficiency.
int risp_isset(risp_t *risp, risp_command_t command);
int risp_getvalue(risp_t *risp, risp_command_t command);
unsigned int risp_getlength(risp_t *risp, risp_command_t command);
char * risp_getdata(risp_t *risp, risp_command_t command);
char * risp_getstring(risp_t *risp, risp_command_t command);

#endif
