#ifndef __RISP_SERVER_PROT_H
#define __RISP_SERVER_PROT_H

#define DEFAULT_PORT      13555


//--------------------------------------------------------------------------------------------------
// The Commands that are part of the 'protocol' for this example.

// No Parameters  - 0x0000 to 0x07ff
#define CMD_NOP                0x0000
#define CMD_HELLO_ACK          0x0001
#define CMD_GOODBYE            0x0002
#define CMD_ECHO               0x0003
#define CMD_NOECHO             0x0004
#define CMD_FOLLOW             0x0005
#define CMD_NOFOLLOW           0x0006
#define CMD_NOUPDATE           0x0007
#define CMD_GET_LATEST_MDG_ID  0x0008

// No Parameters  - 0x8000 to 0x87ff

// 1 byte integer - 0x0800 to 0x0fff

// 2 byte integer - 0x1000 to 0x1fff

// 4 byte integer - 0x2000 to 0x27ff

// 8 byte integer - 0x4000 to 0x47ff
#define CMD_MSG_ID             0x4000
#define CMD_LATEST_MSG_ID      0x4001
#define CMD_SEND_MSG           0x4002
#define CMD_SEND_SINCE         0x4003

// 1 byte string  - 0x8800 to 0x8fff  (max 255 length)
#define CMD_HELLO              0x8800
#define CMD_NAME               0x8801

// 2 byte string  - 0x9000 to 0x97ff  (max 64k length)
#define CMD_MESSAGE            0x9000

// 4 byte string  - 0xa000 to 0xa7ff  (max 4gb length)




#endif

