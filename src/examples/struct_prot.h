#ifndef __STRUCT_SERVER_PROT_H
#define __STRUCT_SERVER_PROT_H

#define DEFAULT_PORT      13556



#define CMD_SEARCH   13

typedef struct {
	unsigned char cmd;
	unsigned char ttl;
	unsigned char len;
	char data[256];
} cmd_search_t;






#endif

