#ifndef __BUFADD_H
#define __BUFADD_H

#include <expbuf.h>
#include <risp.h>

void addCmd(expbuf_t *buf, risp_command_t cmd);
void addCmdShortInt(expbuf_t *buf, risp_command_t cmd, unsigned char value);
void addCmdInt(expbuf_t *buf, risp_command_t cmd, short int value);
void addCmdLargeInt(expbuf_t *buf, risp_command_t cmd, risp_int_t value);
void addCmdShortStr(expbuf_t *buf, risp_command_t cmd, risp_length_t length, char *data);
void addCmdStr(expbuf_t *buf, risp_command_t cmd, risp_length_t length, char *data);
void addCmdLargeStr(expbuf_t *buf, risp_command_t cmd, risp_length_t length, char *data);



#endif

