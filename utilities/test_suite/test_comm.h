#ifndef __TEST_COMM_H__
#define __TEST_COMM_H__

#include <stdint.h>
#include "board.h"
#include "app_error.h"

/*
Comm protocol:
Header(2 btyes) + Type (2 byte) + Len (2 byte) + CRC16 (2 bytes) + Payload (n bytes)
Types:  CMD:    01
        Resp:   02
        ACK:    03
        NACK:   04
        STATUS: 05
        ABORT:  06

Host to device:- CMD packet, Abort packet
Device to host:- Resp, Ack, Nack packets

Ack packet description
{
        Header:                         C8C8
        Type:                           0003
        Len:                            0004
        CRC:                            xxxx
        Payload (Max 255 bytes):        Task ID(4 byte)
}

Nack packet description
{
        Header:                         C3C3
        Type:                           0004
        Len:                            0008
        CRC:                            xxxx
        Payload (Max 255 bytes):        Task ID(4 byte) + Error Code(4 bytes)
}

CMD and Resp packet description
{
        Header:                         C3C3
        Type:                           0001 (CMD), 0002 (Resp)
        Len:                            n
        CRC:                            xxxx
        Payload (Max 255 bytes):        Task ID(4 byte) + Data (n-4 bytes)
}

Abort packet description
{
        Header:                         C3C3
        Type:                           0006 (Abort)
        Len:                            0004
        CRC:                            xxxx
        Payload (Max 255 bytes):        0x00000000
}
*/

#define MAX_PKT_SIZE        HEADER_OFFSET+TASK_ID_SIZE+MAX_PAYLOAD_DATA
#define HEADER_OFFSET       8
#define TASK_ID_SIZE        4
#define MAX_PAYLOAD_DATA    INT8_MAX - HEADER_OFFSET - TASK_ID_SIZE

typedef enum {
    PKT_TYPE_CMD = 0x01,
    PKT_TYPE_RESP = 0x02,
    PKT_TYPE_ACK = 0x03,
    PKT_TYPE_NACK = 0x04,
}pkt_type_t;

typedef enum taskslist{
    TASK_UNUSED=0x00,
    TASK_FLOW_TEST_MASK=0x02000000,
    SEED_GENERATE_TEST,
    SEED_VERIFY_TEST,
    RESTORE_SEED_TEST
}tasks_t;

typedef struct comm_data {
    tasks_t taskid;
    uint16_t len;
    uint8_t data[MAX_PAYLOAD_DATA];
}comm_data_t;

extern comm_data_t recv_data, send_data;
extern uint8_t recv_flag;

extern void com_init(void);
extern void send_to_host();
extern void send_ack();
extern void send_nack(uint32_t error_code);
extern void send_resp(uint8_t *data, uint8_t size);
extern void send_status(uint8_t *data, uint8_t);
#endif
