//-----------------------------------------------------------------------------
// common functionality for the client code.
//-----------------------------------------------------------------------------
#ifndef __RFX_COMMON_H
#define __RFX_COMMON_H


#include <expbuf.h>


#define INVALID_HANDLE -1



// The node structure.  This should be modified to fit your needs, but there 
// should be one for each socket connection that is being processed.  When 
// processing the data stream, the library is not responsible for data that is 
// incomplete.  It will be up to you to make sure that incomplete data is 
// added to a buffer, and re-processed when new data becomes available.
typedef struct {
	int handle;
	expbuf_t in, out;
	int verbose;
	int finished;
	data_t data;

	// local file handling.
	int filehandle;
	unsigned int size, offset;
} node_t;



void processPut(node_t *node);



#endif