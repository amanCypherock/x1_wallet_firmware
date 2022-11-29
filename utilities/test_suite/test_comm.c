#include "stdio.h"
#include "stdint.h"
#include "libusb.h"
#include "communication.h"
#include "circular_queue.h"
#include "crc16.h"
#include "memzero.h"
#include <string.h>

#define HEADER_BYTE 0xC3


typedef enum{
    PKT_HEADER_INDEX1 = 0,
    PKT_HEADER_INDEX2 = 1,
    PKT_TYPE_INDEX    = 2,
    PKT_SIZE_INDEX1   = 3,
    PKT_SIZE_INDEX2   = 4,
    PKT_CRC_INDEX1    = 5,
    PKT_CRC_INDEX2    = 6,
    PKT_PAYLOAD_INDEX = 7
};

uint8_t send_pkt_buff[MAX_PKT_SIZE] = {0};

comm_data_t recv_data = {0}, send_data = {0};
uint8_t recv_flag = 0, send_flag = 0;
uint16_t size = 0;


static uint16_t prepare_packet(pkt_type_t pkt_type);
static void comm_packet_parser(const uint8_t *packet, const uint16_t pkt_len);

void com_init(void)
{
    HAL_PWR_EnableBkUpAccess();
    /* Enable Power Clock*/
    __HAL_RCC_PWR_CLK_ENABLE();

    /* Enable USB power on Pwrctrl CR2 register */
    HAL_PWREx_EnableVddUSB();
    lusb_register_parserFunction(comm_packet_parser);
}

void send_to_host(){
    if(size && send_flag)
        lusb_write(send_pkt_buff, size);
    memzero(send_pkt_buff, size);
    size = 0;
    send_flag = 0;
}

void send_ack(){
    size = 0;
    send_data.taskid = recv_data.taskid;
    send_data.len = 0;
    size = prepare_packet(PKT_TYPE_ACK);
    send_flag = 1;
}

void send_nack(uint32_t error_code){
    size = 0;
    send_data.taskid = recv_data.taskid;
    memcpy(send_data.data, &error_code, sizeof(error_code));
    send_data.len = sizeof(error_code);
    size = prepare_packet(PKT_TYPE_NACK);
    send_flag = 1;
}

void send_resp(uint8_t *data, uint8_t data_len){
    size = 0;
    send_data.taskid = recv_data.taskid;
    memcpy(send_data.data, data, data_len);
    send_data.len = data_len;
    size = prepare_packet(PKT_TYPE_RESP);
    send_flag = 1;
}

static uint16_t prepare_packet(pkt_type_t pkt_type){
    send_pkt_buff[PKT_HEADER_INDEX1] = HEADER_BYTE;
    send_pkt_buff[PKT_HEADER_INDEX2] = HEADER_BYTE;
    send_pkt_buff[PKT_TYPE_INDEX] = pkt_type;
    send_pkt_buff[PKT_SIZE_INDEX1] = (send_data.len + 4) & 0x00FF;
    send_pkt_buff[PKT_SIZE_INDEX2] = ((send_data.len + 4) & 0xFF00)>>8;
    send_data.taskid = swap_32(send_data.taskid);
    memcpy(send_pkt_buff+PKT_PAYLOAD_INDEX, &send_data.taskid, 4);
    if(send_data.len)
        memcpy(send_pkt_buff+PKT_PAYLOAD_INDEX+4, send_data.data, send_data.len);
    uint16_t crc = Cal_CRC16(send_pkt_buff+PKT_PAYLOAD_INDEX, send_pkt_buff[PKT_TYPE_INDEX]);
    send_pkt_buff[PKT_CRC_INDEX1] = crc;
    send_pkt_buff[PKT_CRC_INDEX2] = (send_pkt_buff[PKT_CRC_INDEX2]<<8) | crc;
    return send_pkt_buff[PKT_SIZE_INDEX1] + PKT_PAYLOAD_INDEX;
}

static void comm_packet_parser(const uint8_t *packet, const uint16_t pkt_len){
    if(packet == NULL || pkt_len == 0 || pkt_len > MAX_PKT_SIZE)
        return;

    if(recv_flag == 1){ //last packet not processed
        return;
    }

    uint8_t index = 0;
    uint16_t crc=0;
    static uint8_t pkt_index = PKT_HEADER_INDEX1, payload_len=0;
    while(!recv_flag){
        switch (pkt_index)
        {
        case PKT_HEADER_INDEX1:
        case PKT_HEADER_INDEX2:
            if(packet[index] == HEADER_BYTE)
                pkt_index++;
            break;
        case PKT_HEADER_INDEX:
            if(packet[index] == PKT_TYPE_CMD)
                pkt_index++;
            else{
                pkt_index = PKT_HEADER_INDEX1;
            }
            break;
        case PKT_SIZE_INDEX1:
            if(packet[index] < TASK_ID_SIZE){
                pkt_index = PKT_HEADER_INDEX1;
                break;
            }
            recv_data.len = packet[index] - TASK_ID_SIZE;
            pkt_index++;
            break;
        case PKT_SIZE_INDEX2:

        case PKT_CRC_INDEX1:
            crc = packet[index];
            pkt_index++;
            break;
        case PKT_CRC_INDEX2:
            crc = crc<<8 | packet[index];
            pkt_index++;
            break;
        case PKT_PAYLOAD_INDEX:
            if(payload_len < TASK_ID_SIZE){
                recv_data.taskid = (recv_data.taskid<<8) | packet[index];
                payload_len++;
            }
            else if((payload_len - TASK_ID_SIZE) < recv_data.len){
                recv_data.data[payload_len - TASK_ID_SIZE] = packet[index];
                payload_len++;
            }
            else{
                // if(Cal_CRC16(recv_data.data, recv_data.len) == crc){
                    recv_flag = 1;
                // }
            }
            break;
        default:
            pkt_index=PKT_HEADER_INDEX1;
            break;
        }
        index++;
        if(index > pkt_len)
            break;
    }

    if(recv_flag == 1){
        pkt_index = 0;
        payload_len = 0;
        return 0;
    }
}
