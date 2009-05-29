#ifndef __RFX_PROT_H
#define __RFX_PROT_H

#include <risp.h>
#include <expbuf.h>

#define DEFAULT_PORT      13560



// The Commands that are part of the 'protocol' for this example.

// no param (0 to 31)
#define CMD_NOP          0
#define CMD_CLEAR      	 1
#define CMD_EXECUTE      2
#define CMD_LIST         3
#define CMD_LISTING      4
#define CMD_LISTING_DONE 5
#define CMD_PUT          6
#define CMD_GET          7
#define CMD_FAIL         8

// tiny int (32 to 63)

// int (64 to 95)

// large int (96 to 127)
#define CMD_SIZE         96
#define CMD_OFFSET       97

// short string (128 to 159)
#define CMD_FILE         128

// string (160 to 191)

// large string (192 to 223)
#define CMD_DATA         192


// the variables and flags that represent the data received from commands.
typedef struct {
	risp_command_t op;
	expbuf_t file;
	risp_int_t size;
	risp_int_t offset;
	expbuf_t data;
} data_t;


#endif

