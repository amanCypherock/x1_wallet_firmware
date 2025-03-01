/**
 * @file    controller_old_wallet_b.c
 * @author  Cypherock X1 Team
 * @brief   Old wallet back controller.
 *          Handles post event (only back/cancel events) operations for old wallet flow.
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
#include "controller_level_four.h"
#include "controller_main.h"
#include "controller_old_wallet.h"
#include "tasks.h"

void level_three_old_wallet_controller_b()
{

    switch (flow_level.level_two) {
    case LEVEL_THREE_VIEW_SEED: {
        reset_flow_level();
        counter.next_event_flag = true;
    } break;
    case LEVEL_THREE_DELETE_WALLET: {
        reset_flow_level();
        counter.next_event_flag = true;
    } break;
    case LEVEL_THREE_EXPORT_TO_DESKTOP: {
        export_wallet_controller_b();
    } break;

    case LEVEL_THREE_ADD_COIN: {
        add_coin_controller_b();
    } break;

    case LEVEL_THREE_SEND_TRANSACTION: {
        send_transaction_controller_b();
    } break;

    case LEVEL_THREE_SEND_TRANSACTION_ETH: {
        send_transaction_controller_b_eth();
    } break;

    case LEVEL_THREE_SEND_TRANSACTION_NEAR: {
        send_transaction_controller_near_b();
    } break;

    case LEVEL_THREE_RECEIVE_TRANSACTION: {
        receive_transaction_controller_b();
    } break;

    case LEVEL_THREE_RECEIVE_TRANSACTION_ETH: {
        receive_transaction_controller_b_eth();
    } break;

    case LEVEL_THREE_RECEIVE_TRANSACTION_NEAR: {
        receive_transaction_controller_b_near();
    } break;

    case LEVEL_THREE_WALLET_LOCKED: {
      wallet_locked_controller_b();
      break;
    }

    case LEVEL_THREE_VERIFY_WALLET: {
        verify_wallet_controller_b();
    } break;

    case LEVEL_THREE_SYNC_WALLET: {
        sync_cards_controller_b();
    } break;

    default:
        break;
    }
    return;
}
