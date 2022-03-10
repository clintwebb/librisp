/// 

#include "rispbuf.h"

#if (RISPBUF_VERSION != 0x00000300)
#error "Incorrect header version.  code and header versions must match."
#endif


#include <assert.h>
#include <string.h>

/***** interface functions *****/


void rispbuf_addCmd(expbuf_t *buf, const risp_command_t cmd)
{
	assert(buf);
	assert((cmd >= 0x7000 && cmd <= 0x7fff) || (cmd >= 0xc000));

	risp_length_t olen = risp_command_length(cmd, 0);
	assert(olen == sizeof(risp_command_t));
	assert(sizeof(risp_command_t) == 2);

	if (BUF_AVAIL(buf) <= olen) {
		expbuf_shrink(buf, olen);
	}
	risp_length_t len = risp_addbuf_noparam(BUF_OFFSET(buf), cmd);
	assert(len == olen);
	BUF_LENGTH(buf) += len;
}


void rispbuf_addInt(expbuf_t *buf, const risp_command_t cmd, const risp_int_t value)
{
	assert(sizeof(risp_command_t) == 2);
	assert(buf);
	assert(cmd >= 0x0000 && cmd <= 0x6fff);
	risp_length_t olen = risp_command_length(cmd, 0);
	assert(olen > sizeof(risp_command_t));

	if (BUF_AVAIL(buf) <= olen) {
		expbuf_shrink(buf, olen);
	}
	risp_length_t len = risp_addbuf_int(BUF_OFFSET(buf), cmd, value);
	assert(len == olen);
	BUF_LENGTH(buf) += len;
}


void rispbuf_addStr(expbuf_t *buf, const risp_command_t cmd, const risp_length_t length, const char *data) 
{
	assert(sizeof(risp_command_t) == 2);
	assert(buf);
	assert(cmd >= 0x8000 && cmd <= 0xbfff);
	assert((length > 0 && data) || (length == 0 && data == NULL));

	risp_length_t olen = risp_command_length(cmd, length);
	assert(olen > sizeof(risp_command_t)+length);

	if (BUF_AVAIL(buf) <= olen) {
		expbuf_shrink(buf, olen);
	}
	risp_length_t len = risp_addbuf_str(BUF_OFFSET(buf), cmd, length, (void *)data);
	assert(len == olen);
	BUF_LENGTH(buf) += len;
}




void rispbuf_addBuffer(expbuf_t *buf, const risp_command_t cmd, expbuf_t *src) 
{
	assert(buf);
	assert(cmd >= 0x8000 && cmd <= 0xbfff);
	assert(src);
	rispbuf_addStr(buf, cmd, BUF_LENGTH(src), BUF_DATA(src));

}

