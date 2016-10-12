#ifndef __RISP_SERVER_PROT_H
#define __RISP_SERVER_PROT_H

#define DEFAULT_PORT      13555


//--------------------------------------------------------------------------------------------------
// The Commands that are part of the 'protocol' for this example.

// 1 byte integer - 0x0000 to 0x0fff         0 000 xxxx xxxx
// 2 byte integer - 0x1000 to 0x1fff         0 001 xxxx xxxx	
// 4 byte integer - 0x2000 to 0x2fff         0 010 xxxx xxxx
// 8 byte integer - 0x3000 to 0x3fff         0 011 xxxx xxxx
#define CMD_MSG_ID             0x3000
#define CMD_LATEST_MSG_ID      0x3001
#define CMD_SEND_MSG           0x3002
#define CMD_SEND_SINCE         0x3003

// 16 byte integer - 0x4000 to 0x4fff        0 100 xxxx xxxx
// 32 byte integer - 0x5000 to 0x5fff        0 101 xxxx xxxx
// 64 byte integer - 0x6000 to 0x6fff        0 110 xxxx xxxx
// No Parameters - 0x7000 to 0x7fff          0 111 xxxx xxxx
#define CMD_NOP                0x7000
#define CMD_HELLO_ACK          0x7001
#define CMD_GOODBYE            0x7002
#define CMD_ECHO               0x7003
#define CMD_NOECHO             0x7004
#define CMD_FOLLOW             0x7005
#define CMD_NOFOLLOW           0x7006
#define CMD_NOUPDATE           0x7007
#define CMD_GET_LATEST_MDG_ID  0x7008

// 1 byte-length string - 0x8000 to 0x8fff   1 000 xxxx xxxx
#define CMD_HELLO              0x8000
#define CMD_NAME               0x8001

// 2 byte-length string - 0x9000 to 0x9fff   1 001 xxxx xxxx
#define CMD_MESSAGE            0x9000

// 4 byte-length string - 0xa000 to 0xafff   1 010 xxxx xxxx
// 8 byte-length string - 0xb000 to 0xbfff   1 011 xxxx xxxx
// No Parameters - 0xc000 to 0xffff          1 1xx xxxx xxxx



#endif

