/**
 * @file    export_wallet_tasks.c
 * @author  Cypherock X1 Team
 * @brief   Export wallet task.
 *          This file contains the implementation of the export wallet task.
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
#include "communication.h"
#include "constant_texts.h"
#include "controller_level_four.h"
#include "flash_api.h"
#include "tasks_level_four.h"
#include "ui_delay.h"
#include "ui_instruction.h"
#include "ui_menu.h"

extern Export_Wallet_Data data;

extern lv_task_t* success_task;
extern lv_task_t* timeout_task;

void export_wallet_task()
{
    switch (flow_level.level_three) {
    case EXPORT_WALLET_SELECT_WALLET: {
        char* wallet_names[MAX_WALLETS_ALLOWED];

        uint8_t walletAdded = 0;
        uint8_t walletIndex = 0;

        for (; walletIndex < MAX_WALLETS_ALLOWED; walletIndex++) {
            if (get_wallet_state(walletIndex) == VALID_WALLET &&
                get_wallet_card_state(walletIndex) == 0x0f &&
                get_wallet_locked_status(walletIndex) == 0) {
                wallet_names[walletAdded] = (char *)get_wallet_name(walletIndex);
                walletAdded++;
            }
        }

        menu_init((const char**) wallet_names, walletAdded, ui_text_choose_wallet, false);
    } break;

    case EXPORT_WALLET_FINAL_SCREEN:
        mark_event_over();
        CY_Reset_Not_Allow(true);
        break;
    
    default:
        break;
    }
}