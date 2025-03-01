/**
 * @file    write_to_cards_tasks.c
 * @author  Cypherock X1 Team
 * @brief   Write to cards.
 *          This file contains the task handler to write to cards.
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
#include "constant_texts.h"
#include "controller_main.h"
#include "flash_api.h"
#include "stdint.h"
#include "tasks.h"
#include "ui_instruction.h"
#include "ui_message.h"
#include "tasks_tap_cards.h"


extern char* ALPHABET;
extern char* ALPHA_NUMERIC;
extern char* NUMBERS;



void tap_cards_for_write_flow()
{
    char display[40];

    if (flow_level.level_four > wallet.total_number_of_shares * 2) {
        return;
    }
    switch (flow_level.level_four) {
    case TAP_CARD_ONE_FRONTEND:
    case TAP_CARD_TWO_FRONTEND:
    case TAP_CARD_THREE_FRONTEND:
    case TAP_CARD_FOUR_FRONTEND:
        snprintf(display, sizeof(display), ui_text_tap_x_4_cards, ((flow_level.level_four-1)>>1)+1);
        instruction_scr_init(ui_text_place_card_below, display);
        mark_event_over();
        break;

    case TAP_CARD_ONE_BACKEND:
    case TAP_CARD_TWO_BACKEND:
    case TAP_CARD_THREE_BACKEND:
    case TAP_CARD_FOUR_BACKEND:
        mark_event_over();
        break;

    default:
        message_scr_init(ui_text_something_went_wrong);
        break;
    }
}
