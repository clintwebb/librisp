/// 

#include "bufadd.h"

#include <assert.h>
#include <string.h>

void addCmd(expbuf_t *buf, risp_command_t cmd)
{
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	
	expbuf_add(buf, &cmd, 1);
}


void addCmdLargeInt(expbuf_t *buf, risp_command_t cmd, risp_int_t value)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	
	needed = 1 + 4;
	avail = buf->max - buf->length;
	
	if (avail < needed) { expbuf_shrink(buf, needed); }
	ptr = buf->data + buf->length;
	*ptr++ = cmd;
	*ptr++ = (unsigned char) (value >> 24) & 0xff;
	*ptr++ = (unsigned char) (value >> 16) & 0xff;
	*ptr++ = (unsigned char) (value >> 8) & 0xff;
	*ptr++ = (unsigned char) value & 0xff;
	buf->length += needed;
}



void addCmdShortStr(expbuf_t *buf, risp_command_t cmd, risp_length_t length, char *data)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	
	assert(length > 0);
	assert(length < 256);
	assert(data != NULL);
	
	needed = 1 + 1 + length;
	avail = buf->max - buf->length;
	
	if (avail < needed) { expbuf_shrink(buf, needed); }
	ptr = buf->data + buf->length;
	*ptr++ = cmd;
	*ptr++ = (unsigned char) length;
	memmove(ptr, data, length);
	buf->length += needed;
}

void addCmdLargeStr(expbuf_t *buf, risp_command_t cmd, risp_length_t length, char *data)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(data != NULL);
	
	needed = 1 + 4 + length;
	avail = buf->max - buf->length;
	
	if (avail < needed) { expbuf_shrink(buf, needed); }
	ptr = buf->data + buf->length;
	*ptr++ = cmd;
	*ptr++ = (unsigned char) (length >> 24) & 0xff;
	*ptr++ = (unsigned char) (length >> 16) & 0xff;
	*ptr++ = (unsigned char) (length >> 8) & 0xff;
	*ptr++ = (unsigned char) length & 0xff;
	memmove(ptr, data, length);
	buf->length += needed;
}
