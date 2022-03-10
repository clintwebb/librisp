#ifndef __RISPBUF_H
#define __RISPBUF_H

#include <expbuf.h>
#include <risp.h>

#define RISPBUF_VERSION  0x00000300
#define RISPBUF_VERSION_TEXT  "v0.03.00"


void rispbuf_addCmd(expbuf_t *buf, const risp_command_t cmd);
void rispbuf_addInt(expbuf_t *buf, const risp_command_t cmd, const risp_int_t value);
void rispbuf_addStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data);
void rispbuf_addBuffer(expbuf_t *buf, const risp_command_t cmd, expbuf_t *src);


#endif

