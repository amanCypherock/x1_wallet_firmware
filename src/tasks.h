/**
 * @file    tasks.h
 * @author  Cypherock X1 Team
 * @brief   Header for tasks Enums.
 *          This file contains all the task states encoded in enums.
 * @copyright Copyright (c) 2022 HODL TECH PTE LTD
 * <br/> You may obtain a copy of license at <a href="https://mitcc.org/" target=_blank>https://mitcc.org/</a>
 *
 */
#ifndef TASKS_H
#define TASKS_H

#pragma once

 /**
  * @brief list pf tasks at level one
  *
  *
  */
enum LEVEL_ONE_TASKS { LEVEL_ONE_MAIN_SCREEN };

/**
 * @brief tasks at level two
 *
 */
enum LEVEL_TWO {
    LEVEL_TWO_OLD_WALLET = 1,
    LEVEL_TWO_NEW_WALLET,
    //LEVEL_TWO_ARBITRARY_DATA,
    LEVEL_TWO_ADVANCED_SETTINGS,
};

/**
 * @brief LEVEL THREE ENUMS
 *        FOR NEW WALLET
 */
enum LEVEL_THREE_NEW_WALLET_TASKS {
    LEVEL_THREE_GENERATE_WALLET = 1,
    LEVEL_THREE_RESTORE_WALLET
};

/**
 * @brief LEVEL THREE ENUMS
 *        FOR OLD WALLET
 */
enum LEVEL_THREE_OLD_WALLET_TASKS {
    LEVEL_THREE_VIEW_SEED = 1,
    LEVEL_THREE_DELETE_WALLET,
    LEVEL_THREE_SEND_TRANSACTION,
    LEVEL_THREE_SEND_TRANSACTION_ETH,
    LEVEL_THREE_SEND_TRANSACTION_NEAR,
    LEVEL_THREE_EXPORT_TO_DESKTOP,
    LEVEL_THREE_ADD_COIN,
    LEVEL_THREE_RECEIVE_TRANSACTION,
    LEVEL_THREE_RECEIVE_TRANSACTION_ETH,
    LEVEL_THREE_RECEIVE_TRANSACTION_NEAR,
    LEVEL_THREE_WALLET_LOCKED,
    LEVEL_THREE_VERIFY_WALLET,
    LEVEL_THREE_SYNC_WALLET
};

/**
 * @brief LEVEL THREE ENUMS
 *        FOR ADVANCED SETTINGS
 */
enum LEVEL_THREE_ADVANCED_SETTINGS_TASKS {
#if X1WALLET_MAIN
    LEVEL_THREE_SYNC_CARD_CONFIRM = 1,
    LEVEL_THREE_CARD_HEALTH_CHECK,
    LEVEL_THREE_ROTATE_SCREEN_CONFIRM,
    LEVEL_THREE_TOGGLE_LOGGING,
    LEVEL_THREE_TOGGLE_PASSPHRASE,
    LEVEL_THREE_FACTORY_RESET,
#endif
    LEVEL_THREE_VIEW_DEVICE_VERSION,
    LEVEL_THREE_READ_CARD_VERSION,
#ifdef DEV_BUILD
    LEVEL_THREE_ADJUST_BUZZER,
#endif
    LEVEL_THREE_VERIFY_CARD,
    LEVEL_THREE_READ_CARD_ID,
#if X1WALLET_MAIN
#ifdef DEV_BUILD
    LEVEL_THREE_UPDATE_CARD_ID,
    LEVEL_THREE_CARD_UPGRADE,
#endif
    LEVEL_THREE_SYNC_CARD,
    LEVEL_THREE_SYNC_SELECT_WALLET,
    LEVEL_THREE_SYNC_WALLET_FLOW,
    LEVEL_THREE_ROTATE_SCREEN,
#endif
    LEVEL_THREE_RESET_DEVICE,
    LEVEL_THREE_RESET_DEVICE_CONFIRM,
#ifdef ALLOW_LOG_EXPORT
    LEVEL_THREE_FETCH_LOGS_INIT,
    LEVEL_THREE_FETCH_LOGS_WAIT,
    LEVEL_THREE_FETCH_LOGS,
    LEVEL_THREE_FETCH_LOGS_FINISH,
#endif
#if X1WALLET_MAIN
    LEVEL_THREE_PAIR_CARD,
#elif X1WALLET_INITIAL
    LEVEL_THREE_START_DEVICE_PROVISION,
    LEVEL_THREE_START_DEVICE_AUTHENTICATION,
#else
#error Specify what to build (X1WALLET_INITIAL or X1WALLET_MAIN)
#endif
};

/**
 * @brief LEVEL THREE ENUMS
 *        FOR ARBITRARY DATA
 */
enum FACTORY_RESET_TASKS {
    FACTORY_RESET_INIT = 1,
    FACTORY_RESET_INFO,
    FACTORY_RESET_CONFIRM,
    FACTORY_RESET_TAP_CARD1,
    FACTORY_RESET_TAP_CARD2,
    FACTORY_RESET_CHECK,
    FACTORY_RESET_ERASING,
    FACTORY_RESET_DONE,
    FACTORY_RESET_CANCEL,
};

#if X1WALLET_INITIAL
enum START_DEVICE_PROVISION {
    GENERATE_PROVSION_DATA = 1U,
    PROVISION_SAVE_EXT_KEYS,
    PROVISION_UNSUCCESSFUL,
    PROVISION_STATUS_WAIT
};
#endif


#ifdef ALLOW_LOG_EXPORT
enum START_SEND_LOGS {
    SEND_LOGS_INIT,
    SEND_LOGS_WAIT,
    SEND_LOGS_START,
    SEND_LOGS_FINISH,
};
#endif

/**
 * @brief GENERATE WALLET TASKS
 *
 */
enum GENERATE_WALLET_TASKS {
    GENERATE_WALLET_NAME_INPUT = 1,
    GENERATE_WALLET_NAME_INPUT_CONFIRM,
    GENERATE_WALLET_PIN_INSTRUCTIONS_1,
    GENERATE_WALLET_PIN_INSTRUCTIONS_2,
    GENERATE_WALLET_SKIP_PIN,
    GENERATE_WALLET_PIN_INPUT,
    GENERATE_WALLET_PIN_CONFIRM,
    GENERATE_WALLET_PASSPHRASE_INSTRUCTIONS_1,
    GENERATE_WALLET_PASSPHRASE_INSTRUCTIONS_2,
    GENERATE_WALLET_PASSPHRASE_INSTRUCTIONS_3,
    GENERATE_WALLET_PASSPHRASE_INSTRUCTIONS_4,
    GENERATE_WALLET_SKIP_PASSPHRASE,
    GENERATE_WALLET_PROCESSING,
    GENERATE_WALLET_SEED_GENERATE,
    GENERATE_WALLET_SEED_GENERATED,
    GENERATE_WALLET_SHOW_RANDOMLY_GENERATED_SEEDS_INSTRUCTION,
    GENERATE_WALLET_RANDOM_WORD_VERIFICATION_FAILED,
    GENERATE_WALLET_SHOW_ALL_WORDS,
    GENERATE_WALLET_CONFIRM_RANDOM_WORD_1,
    GENERATE_WALLET_CONFIRM_RANDOM_WORD_2,
    GENERATE_WALLET_CONFIRM_RANDOM_WORD_3,
    GENERATE_WALLET_SAVE_WALLET_SHARE_TO_DEVICE,
    GENERATE_WALLET_TAP_CARD_FLOW,
    GENERATE_WALLET_SUCCESS_MESSAGE,
    GENERATE_WALLET_DELETE,
    GENERATE_WALLET_START_VERIFICATION,
    GENERATE_WALLET_VERIFICATION_PIN_INPUT,
    GENERATE_WALLET_VERIFICATION_TAP_CARDS_FLOW,
    GENERATE_WALLET_VERIFICATION_READ_DEVICE_SHARE,
    GENERATE_WALLET_VERIFY_SEEDS,
    GENERATE_WALLET_VERIFICATION_COMPLETE_INSTRUCTION,
    GENERATE_WALLET_VERIFICATION_WALLET_GENERATED_SUCCESS_MESSAGE,

    GENERATE_WALLET_VERIFICATION_FAILED_DISPLAY,
    GENERATE_WALLET_DELETE_WALLET_ENTER_PIN,
    GENERATE_WALLET_DELETE_WALLET_TAP_CARDS,
    GENERATE_WALLET_DELETE_WALLET_FROM_DEVICE,
    GENERATE_WALLET_DELETE_WALLET_SUCCESSFULL,
    GENERATE_WALLET_REDIRECT_SEED_GENERATE
};

/**
 * @brief DELETE WALLET TASK
 *
 */
enum DELETE_WALLET_TASKS {
    DELETE_WALLET_DUMMY_TASK = 1,
    DELETE_WALLET_ENTER_PIN,
    DELETE_WALLET_TAP_CARDS,
    DELETE_WALLET_FROM_DEVICE,
    DELETE_WALLET_SUCCESS
};

// todo : make flexible for n/k

/**
 * @brief TAP CARDS FLOW
 *
 */
enum TAP_CARDS_FLOW {
    TAP_CARD_ONE_FRONTEND = 1,
    TAP_CARD_ONE_BACKEND,
    TAP_CARD_TWO_FRONTEND,
    TAP_CARD_TWO_BACKEND,
    TAP_CARD_THREE_FRONTEND,
    TAP_CARD_THREE_BACKEND,
    TAP_CARD_FOUR_FRONTEND,
    TAP_CARD_FOUR_BACKEND
};

/**
 * @brief
 *
 */
enum TAP_ONE_CARD_FLOW {
    TAP_ONE_CARD_TAP_A_CARD_DUMMY = 0,
    TAP_ONE_CARD_TAP_A_CARD_FRONTEND,
    TAP_ONE_CARD_TAP_A_CARD_BACKEND,
    TAP_ONE_CARD_SUCCESS_MESSAGE
};

/**
 * @brief
 *
 */
enum PAIR_CARD_FLOW {
    PAIR_CARD_TAP_A_CARD_DUMMY = 0,
    PAIR_CARD_RED_FRONTEND,
    PAIR_CARD_RED_BACKEND,
    PAIR_CARD_BLUE_FRONTEND,
    PAIR_CARD_BLUE_BACKEND,
    PAIR_CARD_GREEN_FRONTEND,
    PAIR_CARD_GREEN_BACKEND,
    PAIR_CARD_YELLOW_FRONTEND,
    PAIR_CARD_YELLOW_BACKEND,
    PAIR_CARD_SUCCESS_MESSAGE
};

/**
 * @brief
 *
 */
enum VERIFY_CARD_FLOW {
    VERIFY_CARD_START_MESSAGE = 1,
    VERIFY_CARD_ESTABLISH_CONNECTION_FRONTEND,
    VERIFY_CARD_ESTABLISH_CONNECTION_BACKEND,
    VERIFY_CARD_FETCH_RANDOM_NUMBER,
    VERIFY_CARD_SIGN_RANDOM_NUMBER_FRONTEND,
    VERIFY_CARD_SIGN_RANDOM_NUMBER_BACKEND,
#if X1WALLET_INITIAL
    VERIFY_CARD_AUTH_STATUS,
    VERIFY_CARD_PAIR_FRONTEND,
    VERIFY_CARD_PAIR_BACKEND,
#endif
    VERIFY_CARD_FINAL_MESSAGE,
    VERIFY_CARD_SUCCESS,
    VERIFY_CARD_FAILED
};

/**
 * @brief
 *
 */
enum EXPORT_WALLET_TASKS {
    EXPORT_WALLET_SELECT_WALLET = 1,
    EXPORT_WALLET_FINAL_SCREEN
};

/**
 * @brief
 *
 */
enum ADD_COINS_TASKS {
    ADD_COINS_VERIFY = 1,
    ADD_COINS_ENTER_PASSPHRASE,
    ADD_COINS_CONFIRM_PASSPHRASE,
    ADD_COINS_CHECK_PIN,
    ADD_COINS_ENTER_PIN,
    ADD_COINS_TAP_CARD,
    ADD_COINS_TAP_CARD_SEND_CMD,
    ADD_COINS_READ_DEVICE_SHARE,
    ADD_COIN_GENERATING_XPUBS,
    ADD_COINS_WAITING_SCREEN,
    ADD_COINS_FINAL_SCREEN
};

/**
 * @brief
 *
 */
enum SEND_TRANSACTION {
    SEND_TXN_VERIFY_COIN = 1,
    SEND_TXN_UNSIGNED_TXN_WAIT_SCREEN,
    SEND_TXN_UNSIGNED_TXN_RECEIVED,
    SEND_TXN_VERIFY_UTXO_FETCH_RAW_TXN,
    SEND_TXN_VERIFY_UTXO,
    SEND_TXN_VERIFY_RECEIPT_ADDRESS,
    SEND_TXN_VERIFY_RECEIPT_AMOUNT,
    SEND_TXN_CHECK_RECEIPT_FEES_LIMIT,
    SEND_TXN_VERIFY_RECEIPT_FEES,
    SEND_TXN_VERIFY_RECEIPT_ADDRESS_SEND_CMD,
    SEND_TXN_ENTER_PASSPHRASE,
    SEND_TXN_CONFIRM_PASSPHRASE,
    SEND_TXN_CHECK_PIN,
    SEND_TXN_ENTER_PIN,
    SEND_TXN_TAP_CARD,
    SEND_TXN_TAP_CARD_SEND_CMD,
    SEND_TXN_READ_DEVICE_SHARE,
    SEND_TXN_SIGN_TXN,
    SEND_TXN_WAITING_SCREEN,
    SEND_TXN_FINAL_SCREEN,
};


/**
 * @brief
 *
 */
enum RECEIVE_TRANSACTION_TASKS {
    RECV_TXN_FIND_XPUB = 1,
    RECV_TXN_ENTER_PASSPHRASE,
    RECV_TXN_CONFIRM_PASSPHRASE,
    RECV_TXN_CHECK_PIN,
    RECV_TXN_ENTER_PIN,
    RECV_TXN_TAP_CARD,
    RECV_TXN_TAP_CARD_SEND_CMD,
    RECV_TXN_READ_DEVICE_SHARE,
    RECV_TXN_DERIVE_ADD_SCREEN,
    RECV_TXN_DERIVE_ADD,
    RECV_TXN_DISPLAY_ADDR,
};


/**
 * @brief
 *
 */
enum SEND_TRANSACTION_ETH {
    SEND_TXN_VERIFY_COIN_ETH = 1,
    SEND_TXN_UNSIGNED_TXN_WAIT_SCREEN_ETH,
    SEND_TXN_UNSIGNED_TXN_RECEIVED_ETH,
    SEND_TXN_VERIFY_CONTRACT_ADDRESS,
    SEND_TXN_VERIFY_TXN_NONCE_ETH,
    SEND_TXN_VERIFY_RECEIPT_ADDRESS_ETH,
    SEND_TXN_CALCULATE_AMOUNT_ETH,
    SEND_TXN_VERIFY_RECEIPT_AMOUNT_ETH,
    SEND_TXN_VERIFY_RECEIPT_FEES_ETH,
    SEND_TXN_VERIFY_RECEIPT_ADDRESS_SEND_CMD_ETH,
    SEND_TXN_ENTER_PASSPHRASE_ETH,
    SEND_TXN_CONFIRM_PASSPHRASE_ETH,
    SEND_TXN_CHECK_PIN_ETH,
    SEND_TXN_ENTER_PIN_ETH,
    SEND_TXN_TAP_CARD_ETH,
    SEND_TXN_TAP_CARD_SEND_CMD_ETH,
    SEND_TXN_READ_DEVICE_SHARE_ETH,
    SEND_TXN_SIGN_TXN_ETH,
    SEND_TXN_WAITING_SCREEN_ETH,
    SEND_TXN_FINAL_SCREEN_ETH
};

/**
 * @brief
 *
 */
enum SEND_TRANSACTION_NEAR {
    SEND_TXN_VERIFY_COIN_NEAR = 1,
    SEND_TXN_UNSIGNED_TXN_WAIT_SCREEN_NEAR,
    SEND_TXN_VERIFY_TXN_NONCE_NEAR,
    SEND_TXN_VERIFY_SENDER_ADDRESS_NEAR,
    SEND_TXN_VERIFY_RECEIPT_ADDRESS_NEAR,
    SEND_TXN_CALCULATE_AMOUNT_NEAR,
    SEND_TXN_VERIFY_RECEIPT_AMOUNT_NEAR,
    SEND_TXN_VERIFY_RECEIPT_FEES_NEAR,
    SEND_TXN_VERIFY_RECEIPT_ADDRESS_SEND_CMD_NEAR,
    SEND_TXN_ENTER_PASSPHRASE_NEAR,
    SEND_TXN_CONFIRM_PASSPHRASE_NEAR,
    SEND_TXN_CHECK_PIN_NEAR,
    SEND_TXN_ENTER_PIN_NEAR,
    SEND_TXN_TAP_CARD_NEAR,
    SEND_TXN_TAP_CARD_SEND_CMD_NEAR,
    SEND_TXN_READ_DEVICE_SHARE_NEAR,
    SEND_TXN_SIGN_TXN_NEAR,
};


/**
 * @brief
 *
 */
enum RECEIVE_TRANSACTION_TASKS_ETH {
    RECV_TXN_FIND_XPUB_ETH = 1,
    RECV_TXN_ENTER_PASSPHRASE_ETH,
    RECV_TXN_CONFIRM_PASSPHRASE_ETH,
    RECV_TXN_ENTER_PIN_ETH,
    RECV_TXN_CHECK_PIN_ETH,
    RECV_TXN_TAP_CARD_ETH,
    RECV_TXN_TAP_CARD_SEND_CMD_ETH,
    RECV_TXN_READ_DEVICE_SHARE_ETH,
    RECV_TXN_DERIVE_ADD_SCREEN_ETH,
    RECV_TXN_DERIVE_ADD_ETH,
    RECV_TXN_DISPLAY_ADDR_ETH,
};

/**
 * @brief
 *
 */
enum RECEIVE_TRANSACTION_TASKS_NEAR {
    RECV_TXN_FIND_XPUB_NEAR = 1,
    RECV_TXN_ENTER_PASSPHRASE_NEAR,
    RECV_TXN_CONFIRM_PASSPHRASE_NEAR,
    RECV_TXN_CHECK_PIN_NEAR,
    RECV_TXN_ENTER_PIN_NEAR,
    RECV_TXN_TAP_CARD_NEAR,
    RECV_TXN_TAP_CARD_SEND_CMD_NEAR,
    RECV_TXN_READ_DEVICE_SHARE_NEAR,
    RECV_TXN_DERIVE_ADD_SCREEN_NEAR,
    RECV_TXN_DERIVE_ADD_NEAR,
    RECV_TXN_WAIT_FOR_LINK_NEAR,
    RECV_TXN_DISPLAY_ACC_NEAR,
    RECV_TXN_DISPLAY_ADDR_NEAR,
    RECV_TXN_WAIT_FOR_REPLACE_NEAR_SCREEN,
    RECV_TXN_WAIT_FOR_REPLACE_NEAR,
    RECV_TXN_SELECT_REPLACE_ACC_NEAR,
    RECV_TXN_VERIFY_SAVE_ACC_NEAR,
    RECV_TXN_FINAL_SCREEN_NEAR,
};

/**
 * @brief
 *
 */
enum START_DEVICE_AUTHENTICATION {
    SIGN_SERIAL_NUMBER = 1,
    SIGN_CHALLENGE,
    AUTHENTICATION_SUCCESS,
    AUTHENTICATION_UNSUCCESSFUL,
#if X1WALLET_INITIAL
    DEVICE_AUTH_INFINITE_WAIT,
#endif
};

/**
 * @brief
 *
 */
enum RESTORE_WALLET_TASKS {
    RESTORE_WALLET_NAME_INPUT = 1,
    RESTORE_WALLET_NAME_CONFIRM,
    RESTORE_WALLET_PIN_INSTRUCTIONS_1,
    RESTORE_WALLET_PIN_INSTRUCTIONS_2,
    RESTORE_WALLET_SKIP_PASSWORD,
    RESTORE_WALLET_PIN_INPUT,
    RESTORE_WALLET_PIN_CONFIRM,
    RESTORE_WALLET_PASSPHRASE_INSTRUCTIONS_1,
    RESTORE_WALLET_PASSPHRASE_INSTRUCTIONS_2,
    RESTORE_WALLET_PASSPHRASE_INSTRUCTIONS_3,
    RESTORE_WALLET_PASSPHRASE_INSTRUCTIONS_4,
    RESTORE_WALLET_SKIP_PASSPHRASE,
    RESTORE_WALLET_NUMBER_OF_WORDS_INPUT,
    RESTORE_WALLET_ENTER_SEED_PHRASE_INSTRUCTION,
    RESTORE_WALLET_ENTER_MNEMONICS,
    RESTORE_WALLET_VERIFY_MNEMONICS_INSTRUCTION,
    RESTORE_WALLET_VERIFY,
    RESTORE_WALLET_CREATING_WAIT_SCREEN,
    RESTORE_WALLET_CREATE,
    RESTORE_WALLET_SAVE_WALLET_SHARE_TO_DEVICE,

    RESTORE_WALLET_TAP_CARDS,
    RESTORE_WALLET_SUCCESS_MESSAGE,
    RESTORE_WALLET_START_VERIFICATION,
    RESTORE_WALLET_VERIFICATION_PIN_INPUT,
    RESTORE_WALLET_VERIFICATION_TAP_CARDS_FLOW,
    RESTORE_WALLET_VERIFY_SEEDS,
    RESTORE_WALLET_VERIFICATION_COMPLETE_INSTRUCTION,
    RESTORE_WALLET_VERIFICATION_WALLET_GENERATED_SUCCESS_MESSAGE,

    RESTORE_WALLET_VERIFICATION_FAILED_DISPLAY,
    RESTORE_WALLET_DELETE_WALLET_ENTER_PIN,
    RESTORE_WALLET_DELETE_WALLET_TAP_CARDS,
    RESTORE_WALLET_DELETE_WALLET_SUCCESSFULL,
    RESTORE_WALLET_REDIRECT_SEED_RESTORE

};

/**
 * @brief
 *
 */
enum ARBITRARY_DATA_TASKS {
    ARBITRARY_DATA_NAME_INPUT = 1,
    ARBITRARY_DATA_NAME_CONFIRM,
    ARBITRARY_DATA_PIN_INSTRUCTIONS_1,
    ARBITRARY_DATA_PIN_INSTRUCTIONS_2,
    ARBITRARY_DATA_SKIP_PIN,
    ARBITRARY_DATA_PIN_INPUT,
    ARBITRARY_DATA_PIN_CONFIRM,
    ARBITRARY_DATA_ENTER_DATA_INSTRUCTION,
    ARBITRARY_DATA_ENTER_DATA,
    ARBITRARY_DATA_CONFIRM_DATA,
    ARBITRARY_DATA_CREATING_WAIT_SCREEN,
    ARBITRARY_DATA_CREATE,

    ARBITRARY_DATA_TAP_CARDS,
    ARBITRARY_DATA_SUCCESS_MESSAGE,
    ARBITRARY_DATA_START_VERIFICATION,
    ARBITRARY_DATA_VERIFICATION_PIN_INPUT,
    ARBITRARY_DATA_VERIFICATION_TAP_CARDS_FLOW,
    ARBITRARY_DATA_VERIFY_DATA,
    ARBITRARY_DATA_VERIFICATION_COMPLETE_INSTRUCTION,
    ARBITRARY_DATA_VERIFICATION_WALLET_GENERATED_SUCCESS_MESSAGE,

    ARBITRARY_DATA_VERIFICATION_FAILED_DISPLAY,
    ARBITRARY_DATA_DELETE_WALLET_ENTER_PIN,
    ARBITRARY_DATA_DELETE_WALLET_TAP_CARDS,
    ARBITRARY_DATA_DELETE_WALLET_SUCCESSFULL,
    ARBITRARY_DATA_REDIRECT_SEED_RESTORE

};

/**
 * @brief
 *
 */
enum RESTORE_WALLET_ENTER_MNEMONICS_TASKS {
    RESTORE_WALLET_ENTER_MNEMONIC = 1,
    RESTORE_WALLET_MNEMONIC_SUGGESTION
};


/**
 * @brief
 *
 */

 /**
  * @brief
  *
  */
enum VIEW_SEED_TASKS {
    VIEW_SEED_DUMMY_TASK = 1,
    VIEW_SEED_ENTER_PIN,
    VIEW_SEED_TAP_CARDS_FLOW,
    VIEW_SEED_READ_DEVICE_SHARE,
    VIEW_SEED_SUCCESS,
    VIEW_SEED_DISPLAY
};

/**
 * @brief
 *
 */
enum WALLET_LOCKED_TASKS {
    WALLET_LOCKED_MESSAGE = 1,
    WALLET_LOCKED_ENTER_PIN,
    WALLET_LOCKED_TAP_CARD_FRONTEND,
    WALLET_LOCKED_TAP_CARD_BACKEND,
    WALLET_LOCKED_SUCCESS,
};

#ifdef DEV_BUILD
enum CARD_UPGRADE_TASKS {
    CARD_UPGRADE_TAP_CARD_MESSAGE = 1,
    CARD_UPGRADE_SELECT_CARD,
    CARD_UPGRADE_FORWARD_MESSAGE
};
#endif

enum VERIFY_WALLET_TASKS {
    VERIFY_WALLET_START = 1,
    VERIFY_WALLET_PIN_INPUT,
    VERIFY_WALLET_TAP_CARDS_FLOW,
    VERIFY_WALLET_READ_DEVICE_SHARE,
    VERIFY_WALLET_SHOW_MNEMONICS,
    VERIFY_WALLET_COMPLETE_INSTRUCTION,
    VERIFY_WALLET_SUCCESS,
    VERIFY_WALLET_DELETE
};

enum SYNC_CARDS_TASKS {
    SYNC_CARDS_START = 1,
    SYNC_CARDS_CURRENT_WALLET_CONFIRM,
    SYNC_CARDS_CHECK_WALLET_PIN,
    SYNC_CARDS_ENTER_PIN_FLOW,
    SYNC_CARDS_TAP_TWO_CARDS_FLOW,
    SYNC_CARDS_GENERATE_DEVICE_SHARE,
    SYNC_CARDS_CHECK_NEXT_WALLET,
    SYNC_CARDS_SUCCESS
};

enum CARD_HC_TASKS {
    CARD_HC_START = 1,
    CARD_HC_TAP_CARD,
    CARD_HC_DISPLAY_CARD_HEALTH,
    CARD_HC_DISPLAY_WALLETS
};
#endif