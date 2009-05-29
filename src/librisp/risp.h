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

#define RISP_VERSION 0x00010000
#define RISP_VERSION_NAME "v1.00.00"


#define RISP_MAX_USER_CMD    256

///////////////////////////////////////////
// create the types that we will be using.

typedef unsigned char      risp_command_t;
typedef unsigned int       risp_length_t;
typedef int                risp_int_t;
typedef unsigned char      risp_char_t;
typedef enum { 
	SUCCESS,
	FAILED
} risp_result_t;


typedef struct {
	void *invalid;
	void *commands[RISP_MAX_USER_CMD];
} risp_t;



///////////////////////////////////////////
// declare the public functions.

// init and shutdown.
risp_t *risp_init(void);
risp_result_t risp_shutdown(risp_t *risp);

// setup of callback commands
risp_result_t risp_add_command(risp_t *risp, risp_command_t command, void *callback);
risp_result_t risp_add_invalid(risp_t *risp, void *callback);

// providing data that needs to be processed and sent to the callback commands.  Will return the number of bytes that were processed.
risp_length_t risp_process(risp_t *risp, void *base, risp_length_t length, risp_char_t *data);

#endif
