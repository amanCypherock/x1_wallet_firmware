/**
 * @file    tap_one_card_tasks.c
 * @author  Cypherock X1 Team
 * @brief   Tap one card task.
 *          This file contains the implementation of the tap one card tasks.
 * @copyright Copyright (c) 2022 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/" target=_blank>https://mitcc.org/</a>
 * 
 ******************************************************************************
 * @attention
 *
 * (c) Copyright 2022 by HODL TECH PTE LTD
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *  
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *  
 *  
 * "Commons Clause" License Condition v1.0
 *  
 * The Software is provided to you by the Licensor under the License,
 * as defined below, subject to the following condition.
 *  
 * Without limiting other conditions in the License, the grant of
 * rights under the License will not include, and the License does not
 * grant to you, the right to Sell the Software.
 *  
 * For purposes of the foregoing, "Sell" means practicing any or all
 * of the rights granted to you under the License to provide to third
 * parties, for a fee or other consideration (including without
 * limitation fees for hosting or consulting/ support services related
 * to the Software), a product or service whose value derives, entirely
 * or substantially, from the functionality of the Software. Any license
 * notice or attribution required by the License must also include
 * this Commons Clause License Condition notice.
 *  
 * Software: All X1Wallet associated files.
 * License: MIT
 * Licensor: HODL TECH PTE LTD
 *
 ******************************************************************************
 */
#include "apdu.h"
#include "communication.h"
#include "constant_texts.h"
#include "controller_main.h"
#include "flash_if.h"
#include "flash_api.h"
#include "nfc.h"
#include "tasks.h"
#include "ui_delay.h"
#include "ui_input_text.h"
#include "ui_instruction.h"
#include "ui_message.h"
#include "utils.h"
#include "pow_utilities.h"
#include "buzzer.h"
#include "tasks_tap_cards.h"


extern char* ALPHABET;
extern char* ALPHA_NUMERIC;
extern char* NUMBERS;
extern char* HEX;
char card_id_fetched[2 * CARD_ID_SIZE + 1];
char card_version[2 * CARD_VERSION_SIZE + 1];


extern bool no_wallet_on_cards;
void tap_a_card_and_sync_task()
{
    switch (flow_level.level_three) { // revert back from level_three to level_four if broken
    case TAP_ONE_CARD_TAP_A_CARD_FRONTEND:
        instruction_scr_init(ui_text_tap_a_card, NULL);
        mark_event_over();
        break;
    case TAP_ONE_CARD_TAP_A_CARD_BACKEND:
        mark_event_over();
        break;
    case TAP_ONE_CARD_SUCCESS_MESSAGE:
        if(no_wallet_on_cards == true){
            reset_flow_level();
            flow_level.show_error_screen = true;
            snprintf(flow_level.error_screen_text, 90, "%s", ui_text_wallet_not_found_on_x1card);
        }
        else{
            delay_scr_init(ui_text_sync_wallets_next_steps, DELAY_TIME);
        }

        break;
    default:
        break;
    }
}

static void get_card_version(char * arr, char message[22]){
    int offset = snprintf(message, 22, "Card version\n ");
    message[offset++] = arr[0],message[offset++] = '.',message[offset++] = arr[1] , message[offset++] = '.' ;
    if(arr[2] != '0')
        message[offset++] = arr[2] , message[offset++] = arr[3];
    else
        message[offset++] = arr[3], message[offset++] = 0;

}

// Command APDU
#define C_APDU_CLA   0
#define C_APDU_INS   1 // instruction
#define C_APDU_P1    2 // parameter 1
#define C_APDU_P2    3 // parameter 2
#define C_APDU_LC    4 // length command
#define C_APDU_DATA  5 // data

#define C_APDU_P1_SELECT_BY_ID   0x00
#define C_APDU_P1_SELECT_BY_NAME 0x04

// Response APDU
#define R_APDU_SW1_COMMAND_COMPLETE 0x90 
#define R_APDU_SW2_COMMAND_COMPLETE 0x00 

#define R_APDU_SW1_NDEF_TAG_NOT_FOUND 0x6a
#define R_APDU_SW2_NDEF_TAG_NOT_FOUND 0x82

#define R_APDU_SW1_FUNCTION_NOT_SUPPORTED 0x6A
#define R_APDU_SW2_FUNCTION_NOT_SUPPORTED 0x81

#define R_APDU_SW1_MEMORY_FAILURE 0x65
#define R_APDU_SW2_MEMORY_FAILURE 0x81

#define R_APDU_SW1_END_OF_FILE_BEFORE_REACHED_LE_BYTES 0x62
#define R_APDU_SW2_END_OF_FILE_BEFORE_REACHED_LE_BYTES 0x82

// ISO7816-4 commands
#define ISO7816_SELECT_FILE 0xA4
#define ISO7816_READ_BINARY 0xB0
#define ISO7816_UPDATE_BINARY 0xD6
#define NDEF_MAX_LENGTH 128  // altough ndef can handle up to 0xfffe in size, arduino cannot.

typedef enum {_NONE, CC, NDEF } tag_file;   // CC ... Compatibility Container

typedef enum {COMMAND_COMPLETE, TAG_NOT_FOUND, FUNCTION_NOT_SUPPORTED, MEMORY_FAILURE, END_OF_FILE_BEFORE_REACHED_LE_BYTES} responseCommand;

void setResponse(responseCommand cmd, uint8_t* buf, uint8_t* sendlen){
  switch(cmd){
  case COMMAND_COMPLETE:
    buf[0] = R_APDU_SW1_COMMAND_COMPLETE;
    buf[1] = R_APDU_SW2_COMMAND_COMPLETE;
    *sendlen += 2;
    break;
  case TAG_NOT_FOUND:
    buf[0] = R_APDU_SW1_NDEF_TAG_NOT_FOUND;
    buf[1] = R_APDU_SW2_NDEF_TAG_NOT_FOUND;
    *sendlen = 2;
    break;
  case FUNCTION_NOT_SUPPORTED:
    buf[0] = R_APDU_SW1_FUNCTION_NOT_SUPPORTED;
    buf[1] = R_APDU_SW2_FUNCTION_NOT_SUPPORTED;
    *sendlen = 2;
    break;
  case MEMORY_FAILURE:
    buf[0] = R_APDU_SW1_MEMORY_FAILURE;
    buf[1] = R_APDU_SW2_MEMORY_FAILURE;
    *sendlen = 2;
    break;
  case END_OF_FILE_BEFORE_REACHED_LE_BYTES:
    buf[0] = R_APDU_SW1_END_OF_FILE_BEFORE_REACHED_LE_BYTES;
    buf[1] = R_APDU_SW2_END_OF_FILE_BEFORE_REACHED_LE_BYTES;
    *sendlen= 2;
    break;
  }
}

uint32_t nfc_setup_target(){
    while (adafruit_pn532_init_as_target() != STM_SUCCESS) 
    {
        reset_inactivity_timer();
    }
}

void tasks_read_card_id()
{
    adafruit_pn532_init(true, 2);
    instruction_scr_init("Waiting for reader", "Emulation mode");
    instruction_scr_change_text("Waiting for reader", true);
    if(nfc_setup_target()==STM_SUCCESS){
	      uint8_t rwbuf[255], rwlen = 255, sendlen = 0;
	      tag_file currentFile;
	      uint8_t taget_status = adafruit_pn532_get_target_status();

          instruction_scr_change_text("Waiting for data read", true);
	      while (1){
                instruction_scr_change_text("Data read", true);

	          if(adafruit_pn532_get_data(rwbuf, &rwlen) != 0){
                  break;
              }

            uint8_t INS = rwbuf[1];
            uint8_t p1 = rwbuf[2];
            uint8_t p2 = rwbuf[3];
            uint8_t lc = rwbuf[4];
            uint16_t p1p2_length = ((int16_t) p1 << 8) + p2;
            switch(rwbuf[C_APDU_INS]){
            case ISO7816_SELECT_FILE:{
              switch(p1){
              case C_APDU_P1_SELECT_BY_ID:{
                if(p2 != 0x0c){
                  setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
                } else if(lc == 2 && rwbuf[C_APDU_DATA] == 0xE1 && (rwbuf[C_APDU_DATA+1] == 0x03 || rwbuf[C_APDU_DATA+1] == 0x04)){
                  setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
                  if(rwbuf[C_APDU_DATA+1] == 0x03){
                    currentFile = CC;
                  } else if(rwbuf[C_APDU_DATA+1] == 0x04){
                    currentFile = NDEF;
                  }
                } else {
                  setResponse(TAG_NOT_FOUND, rwbuf, &sendlen);
                }
              }break;
              case C_APDU_P1_SELECT_BY_NAME: {
                const uint8_t ndef_tag_application_name_v2[] = {0, 0x7, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 };
                if(0 == memcmp(ndef_tag_application_name_v2, rwbuf + C_APDU_P2, sizeof(ndef_tag_application_name_v2))){
                  setResponse(COMMAND_COMPLETE, rwbuf, &sendlen);
               } else{
                  setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
                }
              } break;
              }
            }break;
            case ISO7816_READ_BINARY:{
              switch(currentFile){
              case NONE:{
                  setResponse(TAG_NOT_FOUND, rwbuf, &sendlen);
              }break;
              default:{
                  setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
              }break;
              }
            }break;
            case ISO7816_UPDATE_BINARY:{
                  setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
            }break;
            default:{
              setResponse(FUNCTION_NOT_SUPPORTED, rwbuf, &sendlen);
            }break;
            }

            if(adafruit_pn532_set_data(rwbuf, sendlen) != 0){
              break;
            }

          }
          adafruit_pn532_in_release();
        }
    adafruit_pn532_init(true, 1);

}

void tasks_update_card_id()
{
    switch (flow_level.level_three) {
    case 1: {
        input_text_init(
            HEX,
            ui_text_family_id_hex,
            10,
            DATA_TYPE_TEXT,
            8);
    }

    break;

    case 2: {
        instruction_scr_init(ui_text_tap_a_card, NULL);
        mark_event_over();
    } break;

    case 3: {
        mark_event_over();
    } break;

    case 4:
        message_scr_init(ui_text_successfull);
        break;
    
    default:
        break;
    }
}
