/// 

#include "rispbuf.h"

#if (RISPBUF_VERSION != 0x00000200)
#error "Incorrect header version.  code and header versions must match."
#endif



#include <assert.h>
#include <string.h>

void addCmd(expbuf_t *buf, const risp_command_t cmd)
{
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(cmd >= 0 && cmd <= 63);
	
	expbuf_add(buf, &cmd, 1);
}


void addCmdShortInt(expbuf_t *buf, const risp_command_t cmd, const unsigned char value)
{
	register int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(cmd >= 64 && cmd <= 95);
	
	needed = 1 + 1;
	avail = buf->max - buf->length;
	
	if (avail < needed) { expbuf_shrink(buf, needed); }
	ptr = buf->data + buf->length;
	*ptr++ = cmd;
	*ptr++ = (unsigned char) value & 0xff;
	buf->length += needed;
}



void addCmdInt(expbuf_t *buf, const risp_command_t cmd, const short int value)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(cmd >= 96 && cmd <= 127);
	
	needed = 1 + 2;
	avail = buf->max - buf->length;
	
	if (avail < needed) { expbuf_shrink(buf, needed); }
	ptr = buf->data + buf->length;
	*ptr++ = cmd;
	*ptr++ = (unsigned char) (value >> 8) & 0xff;
	*ptr++ = (unsigned char) value & 0xff;
	buf->length += needed;
}


void addCmdLargeInt(expbuf_t *buf, const risp_command_t cmd, const risp_int_t value)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(cmd >= 128 && cmd <= 159);
	
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



void addCmdShortStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(cmd >= 160 && cmd <= 191);
	
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

void addCmdStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(data != NULL);
	assert(cmd >= 192 && cmd <= 223);
	
	assert(length > 0);
	assert(length < 0xffff);

	needed = 1 + 2 + length;
	avail = buf->max - buf->length;
	
	if (avail < needed) { expbuf_shrink(buf, needed); }
	ptr = buf->data + buf->length;
	*ptr++ = cmd;
	*ptr++ = (unsigned char) (length >> 8) & 0xff;
	*ptr++ = (unsigned char) length & 0xff;
	memmove(ptr, data, length);
	buf->length += needed;
}


void addCmdLargeStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data)
{
	int avail, needed;
	char *ptr;
	
	assert(buf != NULL);
	assert(buf->length <= buf->max);
	assert((buf->data != NULL && buf->max > 0) || (buf->data == NULL && buf->max == 0));
	assert(data != NULL);
	assert(cmd >= 224 && cmd <= 255);
	
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

