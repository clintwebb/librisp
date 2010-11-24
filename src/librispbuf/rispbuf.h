#ifndef __BUFADD_H
#define __BUFADD_H

#include <expbuf.h>
#include <risp.h>

#define RISPBUF_VERSION  0x00000200
#define RISPBUF_VERSION_TEXT  "v0.02.00"


void addCmd(        expbuf_t *buf, const risp_command_t cmd);
void addCmdShortInt(expbuf_t *buf, const risp_command_t cmd, const unsigned char value);
void addCmdInt(     expbuf_t *buf, const risp_command_t cmd, const short int value);
void addCmdLargeInt(expbuf_t *buf, const risp_command_t cmd, const risp_int_t value);
void addCmdShortStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data);
void addCmdStr(     expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data);
void addCmdLargeStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data);

void rispbuf_addCmd(expbuf_t *buf, const risp_command_t cmd);
void rispbuf_addInt(expbuf_t *buf, const risp_command_t cmd, const risp_int_t value);
void rispbuf_addStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data);
void rispbuf_addBuffer(expbuf_t *buf, const risp_command_t cmd, expbuf_t *src);


#endif

