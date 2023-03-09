/**
 * @file    flash_struct.c
 * @author  Cypherock X1 Team
 * @brief   Title of the file.
 *          Short description of the file
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
#include "flash_struct.h"
#include "rfc7539.h"
#include "chacha20poly1305.h"
#include "base58.h"
#include "flash_if.h"
#include "pow_utilities.h"
#include <string.h>
#include "logger.h"
#include "board.h"
#include "assert_conf.h"
#include "memzero.h"
#include "flash_struct_priv.h"

/**
 * @brief (Depricated)Calculates the size of the TLV for memory allocation.
 * 
 * The first 6 bytes consist of 4 bytes of TAG_FLASH_STRUCT + 2 bytes of total structure size.
 * In the calculation 3 is the size of TAG (1 byte) + size of LENGTH (2 bytes) 
 * and 15 is the number of times the TAG, LENGTH, VALUE combination occurs in Flash_Wallet.
 * The number of tags of Flash_Pow are included in the 15 number.
 */
#define FLASH_STRUCT_TLV_SIZE (6 +                                                             \
                               3 + FAMILY_ID_SIZE +                                            \
                               3 + sizeof(uint32_t) +                                          \
                               3 + (MAX_WALLETS_ALLOWED * ((15 * 3) + sizeof(Flash_Wallet))) + \
                               3 + sizeof(uint8_t) +                                           \
                               3 + sizeof(uint8_t))

/**
 * @brief Calculates the size of the device metadata TLV for memory allocation.
 * 
 * The first 6 bytes consist of 4 bytes of TAG_FLASH_DEVICE_METADATA + 2 bytes of total structure size.
 * In the calculation 3 is the size of TAG (1 byte) + size of LENGTH (2 bytes)
 * Device metadata consists of family id, wallet count and wallet metadata
 * Wallet metadata includes wallet id, name and wallet info
 */
#define FLASH_STRUCT_METADATA_TLV_SIZE(wallet_count)     (6 +                       \
                                                    3 + FAMILY_ID_SIZE +            \
                                                    3 + sizeof(uint32_t) +          \
                                                    3 + (wallet_count * (           \
                                                        3 + WALLET_ID_SIZE +        \
                                                        3 + NAME_SIZE +             \
                                                        3 + sizeof(uint8_t))        \
                                                        )                           \
                                                )

/**
 * @brief Calculates the size of the device settings TLV for memory allocation.
 * 
 * The first 6 bytes consist of 4 bytes of TAG_FLASH_DEVICE_METADATA + 2 bytes of total structure size.
 * In the calculation 3 is the size of TAG (1 byte) + size of LENGTH (2 bytes)
 */
#define FLASH_STRUCT_DEVICE_SETTINGS_TLV_SIZE   (6 +                                \
                                                    3 + sizeof(uint8_t) +           \
                                                    3 + sizeof(uint8_t) +           \
                                                    3 + sizeof(uint8_t)             \
                                                )

/**
 * @brief Calculates the size of the wallet state TLV for memory allocation.
 * 
 * The first 6 bytes consist of 4 bytes of TAG_FLASH_DEVICE_METADATA + 2 bytes of total structure size.
 * In the calculation 3 is the size of TAG (1 byte) + size of LENGTH (2 bytes)
 */
#define FLASH_STRUCT_WALLET_STATE_TLV_SIZE(is_locked)     (6 +                      \
                                                    3 + sizeof(uint8_t) +           \
                                                    3 + sizeof(uint8_t) +           \
                                                    3 + sizeof(uint8_t)             \
                                                )

/**
 * @brief Calculates the size of the wallet state TLV for memory allocation.
 * 
 * The first 6 bytes consist of 4 bytes of TAG_FLASH_DEVICE_METADATA + 2 bytes of total structure size.
 * In the calculation 3 is the size of TAG (1 byte) + size of LENGTH (2 bytes)
 */
#define FLASH_STRUCT_WALLET_UNLOCK_DATA_TLV_SIZE     (6 +                           \
                                                    3 + WALLET_ID_SIZE +            \
                                                    3 + NONCE_SIZE                  \
                                                )


/// The size of tlv that will be read and written to flash. Since we read/write in multiples of 4 hence it is essential to make the size divisible by 4.
#define FLASH_STRUCT_TLV_RW_SIZE (FLASH_STRUCT_TLV_SIZE + (FLASH_STRUCT_TLV_SIZE % 4 == 0 ? 0 : 4 - (FLASH_STRUCT_TLV_SIZE % 4)))

#define FLASH_WRITE_STRUCTURE_SIZE sizeof(Flash_Struct)

/// Tags  for TLV
typedef enum Flash_tlv_tags {
    TAG_FLASH_STRUCT = 0xAAAAAAAA,              /// Depricated wallet flash storage tag

    TAG_FLASH_DEVICE_METADATA = 0xABABABAB,     /// Stores device metadata(family id, wallet metadata)
    TAG_FLASH_DEVICE_SETTINGS = 0xBCBCBCBC,     /// Stores device settings
    TAG_FLASH_WALLET_STATES = 0xCDCDCDCD,        /// Stores wallet states
    TAG_FLASH_WALLET_UNLOCK_DATA = 0xDEDEDEDE,  /// Stores wallet unlock data
    TAG_FLASH_BACKUP_DATA = 0xEFEFEFEF,

    TAG_FLASH_FAMILY_ID = 0x01,
    TAG_FLASH_WALLET_COUNT = 0x02,
    TAG_FLASH_WALLET_LIST = 0x03,               /// Depricated wallet lists tag
    TAG_UNUSED_1 = 0x04,                        /// Depricated tag
    TAG_UNUSED_2 = 0x05,                        /// Depricated tag
    TAG_FLASH_DISPLAY_ROTATION = 0x06,
    TAG_FLASH_TOGGLE_PASSPHRASE = 0x07,
    TAG_FLASH_TOGGLE_LOGS = 0x08,

    TAG_FLASH_WALLET = 0x20,
    TAG_FLASH_WALLET_STATE = 0x21,
    TAG_FLASH_WALLET_CARD_STATE = 0x22,
    TAG_FLASH_WALLET_INFO = 0x23,
    TAG_FLASH_WALLET_BUNKER_STATE = 0x24,       /// Depricated tag
    TAG_FLASH_WALLET_PARTIAL_SHARE = 0x25,      /// Depricated tag
    TAG_FLASH_WALLET_NAME = 0x26,
    TAG_FLASH_WALLET_LOCKED = 0x27,
    TAG_FLASH_WALLET_CHALLENGE = 0x28,
    TAG_FLASH_WALLET_ID = 0x29,

    TAG_FLASH_WALLET_CHALLENGE_TARGET = 0x40,
    TAG_FLASH_WALLET_CHALLENGE_RANDOM_NUMBER = 0x41,
    TAG_FLASH_WALLET_CHALLENGE_NONCE = 0x42,
    TAG_FLASH_WALLET_CHALLENGE_CARD_LOCKED = 0x43,
    TAG_FLASH_WALLET_CHALLENGE_TIME_LOCKED = 0x44,

} Flash_tlv_tags;

Flash_Struct flash_ram_instance;
bool is_flash_ram_instance_loaded = false;

static void deserialize_fs(Flash_Struct *flash_struct, uint8_t *tlv);
static uint16_t serialize_fs(const Flash_Struct* flash_struct, uint8_t* tlv);

static uint32_t purge_data(uint8_t* data, uint16_t size, uint32_t start_addr, uint32_t end_addr);

static uint16_t serialize_metadata(const Flash_Struct* flash_struct, uint8_t* tlv);
static uint16_t serialize_device_settings(const Flash_Struct* flash_struct, uint8_t* tlv);
static uint16_t serialize_wallet_state(const Flash_Wallet* wallet, uint8_t* tlv);
static uint16_t serialize_wallet_unlock_data(const Flash_Wallet* wallet, uint8_t* tlv);

static void deserialize_device_metadata(Flash_Struct *flash_struct, uint8_t *tlv);
static void deserialize_wallet_state(Flash_Wallet *flash_wallet, const uint8_t* tlv, const uint16_t len);
static void deserialize_wallet_unlock_data(Flash_Pow* flash_pow, const uint8_t* tlv, const uint16_t len);

static void backup_data(uint8_t *tlv_data, uint16_t tlv_data_size);
static uint16_t read_backup_data();
static void reset_backup_data();

static uint32_t get_latest_device_metadata(const Flash_Struct* flash_struct);
static uint32_t get_latest_device_state(const Flash_Struct* flash_struct);
static uint32_t get_latest_wallet_unlock_data(const Flash_Struct* flash_struct);

/**
 * @brief Load flash struct instance (depricated)
 *
 */
static void flash_struct_load()
{
    ASSERT((&flash_ram_instance) != NULL);
#if USE_SIMULATOR == 1
    uint8_t serialized_flash_metadata[8];
    read_cmd(FLASH_DATA_ADDRESS, serialized_flash_metadata, 8);
#else
    uint8_t *serialized_flash_metadata = (uint8_t *)FLASH_DATA_ADDRESS;
#endif
    uint32_t serialized_flash_struct_tag = serialized_flash_metadata[0] + (serialized_flash_metadata[1] << 8) + (serialized_flash_metadata[2] << 16) + (serialized_flash_metadata[3] << 24);
    uint16_t serialized_flash_size = serialized_flash_metadata[4] + (serialized_flash_metadata[5] << 8);

    if (serialized_flash_struct_tag == TAG_FLASH_STRUCT && serialized_flash_size <= FLASH_DATA_SIZE_LIMIT) {
        // 6 is added to include the TAG_FLASH_STRUCT and length of the serialized structure
        uint16_t serialized_flash_size_tagged = serialized_flash_size + 6;
        
        uint8_t *serialized_flash_instance = (uint8_t *)malloc(serialized_flash_size_tagged);
        ASSERT(serialized_flash_instance != NULL);
        read_cmd(FLASH_DATA_ADDRESS, (uint32_t *)serialized_flash_instance, serialized_flash_size_tagged);
        deserialize_fs(&flash_ram_instance, serialized_flash_instance);
        free(serialized_flash_instance);
        serialized_flash_instance = NULL;
    }
    else if(serialized_flash_struct_tag == TAG_FLASH_DEVICE_METADATA){
        get_latest_device_metadata(&flash_ram_instance);
        get_latest_device_state(&flash_ram_instance);
        get_latest_wallet_unlock_data(&flash_ram_instance);
    }
    else {
        LOG_CRITICAL("xxxa");
        erase_cmd(FLASH_DATA_ADDRESS, FLASH_STRUCT_TLV_SIZE);
        memset(&flash_ram_instance, DEFAULT_VALUE_IN_FLASH, FLASH_WRITE_STRUCTURE_SIZE);
    }

    if (flash_ram_instance.wallet_count == DEFAULT_UINT32_IN_FLASH) {
        flash_ram_instance.wallet_count = 0;
    }
}

/**
 * @brief Get the flash ram instance object
 *
 * @return const Flash_Struct*
 */
const Flash_Struct* get_flash_ram_instance()
{
    ASSERT((&flash_ram_instance) != NULL);

    if (!is_flash_ram_instance_loaded) {
        flash_struct_load();
        is_flash_ram_instance_loaded = true;
    }
    return &flash_ram_instance;
}

/**
 * @brief 
 * 
 */
void flash_erase()
{
    erase_cmd(FLASH_DATA_ADDRESS, FLASH_STRUCT_TLV_SIZE);
    memset(&flash_ram_instance, DEFAULT_VALUE_IN_FLASH, FLASH_WRITE_STRUCTURE_SIZE);

    if (flash_ram_instance.wallet_count == DEFAULT_UINT32_IN_FLASH) {
        flash_ram_instance.wallet_count = 0;
    }
    is_flash_ram_instance_loaded = false;
}

/**
 * @brief Fills the TLV for the passed tag and passed flash object.
 * flash_obj is type casted to an appropriate struct type before accessing its members.
 * 
 * @param array TLV array
 * @param starting_index Pointer to the index of the current location in tlv
 * @param tag Flash_tlv_tags tag for TLV
 * @param length Size of the value
 * @param data Byte data array that will be filled in the TLV array
 */
static void fill_flash_tlv(uint8_t* array, uint16_t* starting_index, const uint8_t tag, const uint16_t length, const uint8_t* data){
    
    array[(*starting_index)++] = tag;
    array[(*starting_index)++] = length;
    array[(*starting_index)++] = (length >> 8);

    memcpy(array + *starting_index, data, length);
    *starting_index = *starting_index + length;
}

/**
 * @brief Finds the address of the last empty 8-byte aligned word in a range of flash memory
 *
 * This function reads backwards from the end_address to the start_address of the flash memory
 * and returns the address of the last 8-byte aligned empty flash word. If no empty word is found,
 * the function returns 0xFFFFFFFF to indicate failure.
 *
 * @param[in] start_address The start address of the range to search (inclusive)
 * @param[in] end_address The end address of the range to search (inclusive)
 *
 * @return The address of the last empty 8-byte aligned word in the range, or 0xFFFFFFFF if no empty word is found
 */
uint32_t find_last_empty_address(uint32_t start_address, uint32_t end_address) {
  uint32_t address = end_address;

  // Round down to the last 8-byte aligned address
  address = address & ~7;

  // Loop backwards through the flash memory from the end_address to the start_address
  while (address >= start_address) {
    uint64_t value = *(volatile uint64_t*)address;

    // Check if the value is equal to 0xFFFFFFFFFFFFFFFF
    if (value != 0xFFFFFFFFFFFFFFFF) {
      // Value is not empty, move to the previous 8-byte aligned address
      address -= 8;
    } else {
      // Value is empty, return the current address
      return address;
    }
  }

  // No empty address found
  return 0xFFFFFFFF;
}

static void backup_data(uint8_t *tlv_data, uint16_t tlv_data_size){

    uint32_t backup_tag[2] = {TAG_FLASH_BACKUP_DATA, TAG_FLASH_BACKUP_DATA};

    
    uint32_t backup_write_address = find_last_empty_address(FLASH_DATA_BACKUP_ADDRESS, FLASH_DATA_BACKUP_END_ADDRESS);
    if(FLASH_DATA_BACKUP_END_ADDRESS - backup_write_address <= tlv_data_size){
        erase_cmd(FLASH_DATA_BACKUP_ADDRESS, FLASH_WALLET_METADATA_SIZE_LIMIT);
    }

    write_cmd(backup_write_address, backup_tag, 8);
    write_cmd(backup_write_address + 8, (uint32_t *)tlv_data, tlv_data_size);
}

static void reset_backup_data(){
    uint32_t* current_address = (uint32_t*) FLASH_DATA_BACKUP_ADDRESS;

    while(current_address < FLASH_DATA_BACKUP_END_ADDRESS){
        // Check if this is the backup tag or zeroed value
        if(*current_address == TAG_FLASH_BACKUP_DATA && *current_address+1 == TAG_FLASH_BACKUP_DATA){
            // Zero-ise the backup tag
            uint32_t zero_data[2] = {0};
            write_cmd(current_address, zero_data, 8);
        }
        else if(!(*current_address == 0 && *current_address+1 == 0)){
            continue;
        }

        // Skip over TLV data
        uint16_t length = (uint16_t) (*(uint16_t*)(current_address + 3));  // Read length from address 
        length += (8 + 6);              // Add 8byte backup tag and tlv offset  
        length = ((length + 7)/8)*8;    // Align length to 8 byte offset  

        current_address += length/4;
    }
}

/**
 * @brief Save device metadata to flash cyclically
 *        Refer FLASH_STRUCT_METADATA_TLV_SIZE for data associated with TAG_FLASH_DEVICE_METADATA tag
*/
static uint32_t save_device_metadata(){
    ASSERT((&flash_ram_instance) != NULL);

    uint32_t write_address = find_last_empty_address(FLASH_WALLET_METADATA_ADDRESS, FLASH_WALLET_METADATA_END_ADDRESS);
    uint16_t serialized_flash_size = FLASH_STRUCT_METADATA_TLV_SIZE(flash_ram_instance.wallet_count);
    uint8_t *serialized_flash_instance = (uint8_t *)malloc(serialized_flash_size);
    ASSERT(serialized_flash_instance != NULL);

    if(serialized_flash_size >= (FLASH_WALLET_METADATA_END_ADDRESS - (uint32_t)write_address)){
        // Purge operation required as flash filled completely

        // Read current metadata into temporary flash struct
        Flash_Struct current_device_metadata = {0};
        if(get_latest_device_metadata(&current_device_metadata) != 0){
            return 1;
        }

        uint16_t serialized_flash_size = FLASH_STRUCT_METADATA_TLV_SIZE(current_device_metadata.wallet_count);
        uint8_t *serialized_flash_instance = (uint8_t *)malloc(serialized_flash_size);
        ASSERT(serialized_flash_instance != NULL);


        // Serialize metadata
        serialize_metadata(&current_device_metadata, serialized_flash_instance);



        if(purge_device_metadata() != 0){
            return 2;
        }
    }

    if(serialize_metadata(&flash_ram_instance, serialized_flash_instance) != serialized_flash_size){
        return 3;
    }

    write_cmd(write_address, (uint32_t *)serialized_flash_instance, serialized_flash_size);
    free(serialized_flash_instance);
    serialized_flash_instance = NULL;
    return 0;
}

/**
 * @brief Save device settings to flash cyclically
 *        Refer FLASH_STRUCT_METADATA_TLV_SIZE for data associated with TAG_FLASH_DEVICE_METADATA tag
*/
static uint32_t save_device_settings(){
    ASSERT((&flash_ram_instance) != NULL);

    uint32_t write_address = find_last_empty_address(FLASH_DEVICE_STATE_ADDRESS, FLASH_DEVICE_STATE_END_ADDRESS);
    uint8_t *serialized_flash_instance = (uint8_t *)malloc(FLASH_STRUCT_DEVICE_SETTINGS_TLV_SIZE);
    ASSERT(serialized_flash_instance != NULL);

    if(FLASH_STRUCT_DEVICE_SETTINGS_TLV_SIZE >= (FLASH_DEVICE_STATE_END_ADDRESS - (uint32_t)write_address)){
        // Purge operation required
        if(purge_device_state() != 0){
            return 2;
        }
    }

    if(serialize_device_settings(&flash_ram_instance, serialized_flash_instance) != FLASH_STRUCT_DEVICE_SETTINGS_TLV_SIZE){
        return 3;
    }

    write_cmd(write_address, (uint32_t *)serialized_flash_instance, FLASH_STRUCT_DEVICE_SETTINGS_TLV_SIZE);
    free(serialized_flash_instance);
    serialized_flash_instance = NULL;
    return 0;
}

/**
 * @brief Save device metadata to flash cyclically
 *        Refer FLASH_STRUCT_METADATA_TLV_SIZE for data associated with TAG_FLASH_DEVICE_METADATA tag
*/
static uint32_t save_wallet_state(uint8_t *wallet_id){
    ASSERT((&flash_ram_instance) != NULL && wallet_id!= NULL);

    int i=0;
    for (i=0; i<4; i++){
        if(memcmp(wallet_id, flash_ram_instance.wallets[i].wallet_id, WALLET_ID_SIZE) == 0){
            break;
        }
    }

    if(i >= 4){
        return 1;
    }

    uint32_t write_address = find_last_empty_address(FLASH_DEVICE_STATE_ADDRESS, FLASH_DEVICE_STATE_END_ADDRESS);
    uint16_t serialized_flash_size = FLASH_STRUCT_WALLET_STATE_TLV_SIZE(flash_ram_instance.wallets[i].is_wallet_locked);
    uint8_t *serialized_flash_instance = (uint8_t *)malloc(serialized_flash_size);
    ASSERT(serialized_flash_instance != NULL);

    if(serialized_flash_size >= (FLASH_DEVICE_STATE_END_ADDRESS - (uint32_t)write_address)){
        // Purge operation required as flash filled completely
        if(purge_device_state() != 0){
            return 2;
        }
    }

    if(serialize_wallet_state(&flash_ram_instance.wallets[i], serialized_flash_instance) != serialized_flash_size){
        return 3;
    }

    write_cmd(write_address, (uint32_t *)serialized_flash_instance, serialized_flash_size);
    free(serialized_flash_instance);
    serialized_flash_instance = NULL;
    return 0;
}

/**
 * @brief Save device metadata to flash cyclically
 *        Refer FLASH_STRUCT_METADATA_TLV_SIZE for data associated with TAG_FLASH_DEVICE_METADATA tag
*/
static uint32_t save_wallet_unlock_data(uint8_t *wallet_id){
    ASSERT((&flash_ram_instance) != NULL && wallet_id!= NULL);

    int i=0;
    for (i=0; i<4; i++){
        if(memcmp(wallet_id, flash_ram_instance.wallets[i].wallet_id, WALLET_ID_SIZE) == 0){
            break;
        }
    }

    if(i >= 4){
        return 1;
    }

    uint32_t write_address = find_last_empty_address(FLASH_WALLET_UNLOCK_ADDRESS, FLASH_WALLET_UNLOCK_END_ADDRESS);
    uint8_t *serialized_flash_instance = (uint8_t *)malloc(FLASH_STRUCT_WALLET_UNLOCK_DATA_TLV_SIZE);
    ASSERT(serialized_flash_instance != NULL);

    if(FLASH_STRUCT_WALLET_UNLOCK_DATA_TLV_SIZE >= (FLASH_WALLET_UNLOCK_END_ADDRESS - (uint32_t)write_address)){
        // Purge operation required as flash filled completely
        if(purge_wallet_unlock_data() != 0){
            return 2;
        }
    }

    if(serialize_wallet_unlock_data(&flash_ram_instance.wallets[i], serialized_flash_instance) != FLASH_STRUCT_WALLET_UNLOCK_DATA_TLV_SIZE){
        return 3;
    }

    write_cmd(write_address, (uint32_t *)serialized_flash_instance, FLASH_STRUCT_WALLET_UNLOCK_DATA_TLV_SIZE);
    free(serialized_flash_instance);
    serialized_flash_instance = NULL;
    return 0;
}


/**
 * @brief Get the latest entry of device metadata from flash
 * 
 * @param flash_struct is populated from the latest metadata entry on flash
 * @return  0 - successfully read data
 *          1 - tag not found
*/
static uint32_t get_latest_device_metadata(const Flash_Struct* flash_struct){
    ASSERT(flash_struct != NULL);

    // Get a pointer to the start of the metadata area
    uint8_t* ptr = (uint32_t*) FLASH_WALLET_METADATA_ADDRESS;

    // Initialize variables to hold the latest tag value and length found so far
    uint8_t* latest_value_ptr = NULL;
    uint16_t latest_length = 0;

    // Loop through the metadata TLV data
    while (ptr < (uint32_t*) FLASH_WALLET_METADATA_END_ADDRESS) {
        // Read the tag and length fields from 8-byte aligned addresses
        uint32_t tag = *(uint32_t*)ptr;
        uint16_t length = (uint16_t) *(ptr + 4);
        uint8_t* value_ptr = ptr + 6;

        // Check if this is the tag we're looking for
        if (tag == TAG_FLASH_DEVICE_METADATA) {
            // Found the tag, save pointer and length
            latest_value_ptr = value_ptr;
            latest_length = length;
        }
        // Move to the next TLV entry
        ptr += ((length + 6 + 7)/8)*8;
    }

    if(latest_value_ptr == NULL){
        // No data present
        return 1;
    }
    deserialize_device_metadata(flash_struct, latest_value_ptr);

    return 0;
}

/**
 * @brief Get the latest entry of device metadata from flash
 * 
 * @param[in] flash_struct is populated from the latest metadata entry on flash
 * @return  0 - successfully read data
 *          1 - tag not found
*/
static uint32_t get_latest_device_state(const Flash_Struct* flash_struct){
    ASSERT(flash_struct != NULL);

    // Get a pointer to the start of the metadata area
    uint8_t* ptr = (uint32_t*) FLASH_DEVICE_STATE_ADDRESS;

    // Initialize variables to hold the latest tag value and length found so far
    uint8_t* settings_value_ptr = NULL;
    uint16_t settings_length = 0;

    // Loop through the device state TLV data
    while (ptr < (uint32_t*) FLASH_WALLET_METADATA_END_ADDRESS) {
        // Read the tag and length fields from 8-byte aligned addresses
        uint32_t tag = *(uint32_t*)ptr;
        uint16_t length = (uint16_t) *(ptr + 4);
        uint8_t* value_ptr = ptr + 6;

        // Check if this is the tag we're looking for
        if (tag == TAG_FLASH_DEVICE_SETTINGS) {
            // Found the settings tag, save pointer and length
            settings_value_ptr = value_ptr;
            settings_length = length;
        }

        if ((tag == TAG_FLASH_WALLET_STATES) && (value_ptr[0] == TAG_FLASH_WALLET_ID)) {
            // Found a wallet state, populate to ram instance
            uint8_t wallet_id[WALLET_ID_SIZE] = {0};
            memcpy(wallet_id, &value_ptr[3], WALLET_ID_SIZE);

            for (int i=0; i<4; i++){
                if(memcmp(wallet_id, flash_struct->wallets[i].wallet_id, WALLET_ID_SIZE) == 0){
                    deserialize_wallet_state(&(flash_struct->wallets[i]), value_ptr, length);
                    break;
                }
            }
        }
        // Move to the next TLV entry
        ptr += ((length + 6 + 7)/8)*8;

    }

    if(settings_value_ptr == NULL){
        // No data present
        return 1;
    }

    deserialize_device_settings(flash_struct, settings_value_ptr, settings_length);
    return 0;
}

static uint32_t get_latest_wallet_unlock_data(const Flash_Struct* flash_struct){
    ASSERT(flash_struct != NULL);

    // Get a pointer to the start of the metadata area
    uint8_t* ptr = (uint32_t*) FLASH_DEVICE_STATE_ADDRESS;

    // Loop through the device state TLV data
    while (ptr < (uint32_t*) FLASH_WALLET_METADATA_END_ADDRESS) {
        // Read the tag and length fields from 8-byte aligned addresses
        uint32_t tag = *(uint32_t*)ptr;
        uint16_t length = (uint16_t) *(ptr + 4);
        uint8_t* value_ptr = ptr + 6;

        if ((tag == TAG_FLASH_WALLET_UNLOCK_DATA) && (value_ptr[0] == TAG_FLASH_WALLET_ID)) {
            // Found wallet unlock data, populate to ram instance
            uint8_t wallet_id[WALLET_ID_SIZE] = {0};
            memcpy(wallet_id, &value_ptr[3], WALLET_ID_SIZE);

            for (int i=0; i<4; i++){
                if(memcmp(wallet_id, flash_struct->wallets[i].wallet_id, WALLET_ID_SIZE) == 0){
                    deserialize_wallet_unlock_data(&(flash_struct->wallets[i].challenge), value_ptr, length);
                    break;
                }
            }
        }
        // Move to the next TLV entry
        ptr += ((length + 6 + 7)/8)*8;

    }

    return 0;
}

/**
 * @brief Read latest device metadata from flash TLV and re-write 
 *        the data at start after erasing metadata area
 * 
 * @return  0 - Successfully erased and written default data
 *          1 - Could not read any relevant data on flash
 */
static uint32_t purge_data(uint8_t* data, uint16_t size, uint32_t start_addr, uint32_t end_addr){
    // Write to backup storage
    backup_data(data, size);

    erase_cmd(start_addr, end_addr);

    write_cmd(start_addr, (uint32_t *)data, size);
 
    reset_backup_data();

    return 0;
}

static uint32_t purge_device_state(){
    uint32_t backup_tag[2] = {TAG_FLASH_BACKUP_DATA, TAG_FLASH_BACKUP_DATA};
    Flash_Struct current_device_metadata = {0};
    uint16_t serialized_flash_size = FLASH_STRUCT_METADATA_TLV_SIZE(current_device_metadata.wallet_count);
    uint8_t *serialized_flash_instance = (uint8_t *)malloc(serialized_flash_size);
    ASSERT(serialized_flash_instance != NULL);

    if(get_latest_device_metadata(&current_device_metadata) != 0){
        return 1;
    }

    serialize_metadata(&current_device_metadata, serialized_flash_instance);

    uint32_t backup_write_address = find_last_empty_address(FLASH_DATA_BACKUP_ADDRESS, FLASH_DATA_BACKUP_END_ADDRESS);
    if(FLASH_DATA_BACKUP_END_ADDRESS - backup_write_address <= serialized_flash_size){
        erase_cmd(FLASH_DATA_BACKUP_ADDRESS, FLASH_WALLET_METADATA_SIZE_LIMIT);
    }

    write_cmd(backup_write_address, backup_tag, 8);
    write_cmd(backup_write_address + 8, (uint32_t *)serialized_flash_instance, serialized_flash_size);

    erase_cmd(FLASH_WALLET_METADATA_ADDRESS, FLASH_WALLET_METADATA_SIZE_LIMIT);
    write_cmd(FLASH_WALLET_METADATA_ADDRESS, (uint32_t *)serialized_flash_instance, FLASH_STRUCT_TLV_SIZE);

    memset(backup_tag, 0, sizeof(backup_tag));
    write_cmd(backup_write_address, backup_tag, 8);    

    free(serialized_flash_instance);
    serialized_flash_instance = NULL;

    return 0;
}

/**
 * @brief Function to fill the TLV with the properties of Flash_Wallet struct.
 * 
 * @param array TLV array
 * @param starting_index Pointer to the index of the current location in tlv
 * @param tag Flash_tlv_tags tag for TLV
 * @param length Size of the value
 * @param flash_struct Pointer to the Flash_Struct instance ot access the list of Flash_Wallet structs
 */
static void serialize_wallet_metadata(uint8_t* array, uint16_t* starting_index, const Flash_Struct* flash_struct) {
    const Flash_Wallet *wallet = NULL;

    for(uint8_t wallet_index = 0; wallet_index<MAX_WALLETS_ALLOWED; wallet_index++) {
        array[(*starting_index)++] = TAG_FLASH_WALLET;

        uint16_t len_index = (*starting_index);
        (*starting_index) += 2;
        wallet = &(flash_struct->wallets[wallet_index]);
        
        if(wallet->state != VALID_WALLET || 
            wallet->state != UNVERIFIED_VALID_WALLET || 
            wallet->state != INVALID_WALLET || 
            wallet->state != VALID_WALLET_WITHOUT_DEVICE_SHARE){
                continue;
        }

        fill_flash_tlv(array, starting_index, TAG_FLASH_WALLET_INFO, sizeof(wallet->wallet_info), &(wallet->wallet_info));
        fill_flash_tlv(array, starting_index, TAG_FLASH_WALLET_NAME, NAME_SIZE, (uint8_t *) (&(wallet->wallet_name)));
        fill_flash_tlv(array, starting_index, TAG_FLASH_WALLET_ID, WALLET_ID_SIZE,  (uint8_t *) (&(wallet->wallet_id)));

        array[len_index] = (*starting_index) - len_index - 2;
        array[len_index + 1] = ((*starting_index) - len_index - 2) >> 8;
    }
}

/**
 * @brief Create a tlv from the passed flash_struct object.
 * 
 * @param flash_struct Flash Struct pointer
 * @param tlv TLV array 
 * @return uint32_t Size of the TLV
 */
static uint16_t serialize_metadata(const Flash_Struct* flash_struct, uint8_t* tlv) {
    tlv[0] = (uint8_t)(TAG_FLASH_DEVICE_METADATA);
    tlv[1] = (uint8_t)(TAG_FLASH_DEVICE_METADATA >> 8);
    tlv[2] = (uint8_t)(TAG_FLASH_DEVICE_METADATA >> 16);
    tlv[3] = (uint8_t)(TAG_FLASH_DEVICE_METADATA >> 24);
    uint16_t index = 6;

    fill_flash_tlv(tlv, &index, TAG_FLASH_FAMILY_ID, sizeof(flash_ram_instance.family_id), flash_ram_instance.family_id);
    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_COUNT, sizeof(flash_ram_instance.wallet_count), flash_ram_instance.wallet_count);

    serialize_wallet_metadata(tlv, &index, flash_struct);

    tlv[4] = index - 6;
    tlv[5] = (index - 6) >> 8 ;

    return index;

}

/**
 * @brief Create a tlv from the passed flash_struct object.
 * 
 * @param flash_struct Flash Struct pointer
 * @param tlv TLV array 
 * @return uint32_t Size of the TLV
 */
static uint16_t serialize_device_settings(const Flash_Struct* flash_struct, uint8_t* tlv) {
    tlv[0] = (uint8_t)(TAG_FLASH_DEVICE_SETTINGS);
    tlv[1] = (uint8_t)(TAG_FLASH_DEVICE_SETTINGS >> 8);
    tlv[2] = (uint8_t)(TAG_FLASH_DEVICE_SETTINGS >> 16);
    tlv[3] = (uint8_t)(TAG_FLASH_DEVICE_SETTINGS >> 24);
    uint16_t index = 6;

    fill_flash_tlv(tlv, &index, TAG_FLASH_DISPLAY_ROTATION, sizeof(flash_struct->displayRotation), &(flash_struct->displayRotation));
    fill_flash_tlv(tlv, &index, TAG_FLASH_TOGGLE_PASSPHRASE, sizeof(flash_struct->enable_passphrase), &(flash_struct->enable_passphrase));
    fill_flash_tlv(tlv, &index, TAG_FLASH_TOGGLE_LOGS, sizeof(flash_struct->enable_log), &(flash_struct->enable_log));

    tlv[4] = index - 6;
    tlv[5] = (index - 6) >> 8 ;

    return index;
}

/**
 * @brief Function to fill the TLV with the properties of Flash_Pow struct.
 * 
 * @param array TLV array
 * @param starting_index Pointer to the index of the current location in tlv
 * @param tag Flash_tlv_tags tag for TLV
 * @param length Size of the value
 * @param flash_pow Pointer to the Flash_Pow instance
 */
static void serialize_pow(uint8_t* array, uint16_t* starting_index, const Flash_Pow* flash_pow){

    array[(*starting_index)++] = TAG_FLASH_WALLET_CHALLENGE;

    uint16_t pow_len_index = (*starting_index);
    (*starting_index) += 2;

    fill_flash_tlv(array, starting_index, TAG_FLASH_WALLET_CHALLENGE_TARGET, SHA256_SIZE, (uint8_t *) flash_pow->target);
    fill_flash_tlv(array, starting_index, TAG_FLASH_WALLET_CHALLENGE_RANDOM_NUMBER, POW_RAND_NUMBER_SIZE, (uint8_t *) flash_pow->random_number);
    fill_flash_tlv(array, starting_index, TAG_FLASH_WALLET_CHALLENGE_CARD_LOCKED, sizeof(flash_pow->card_locked), (uint8_t *) (&(flash_pow->card_locked)));

    array[pow_len_index] = (*starting_index) - pow_len_index - 2;
    array[pow_len_index + 1] = ((*starting_index) - pow_len_index - 2) >> 8;
}

/**
 * @brief Create a tlv from the passed flash_struct object.
 * 
 * @param flash_struct Flash Struct pointer
 * @param tlv TLV array 
 * @return uint32_t Size of the TLV
 */
static uint16_t serialize_wallet_state(const Flash_Wallet* wallet, uint8_t* tlv) {
    tlv[0] = (uint8_t)(TAG_FLASH_WALLET_STATES);
    tlv[1] = (uint8_t)(TAG_FLASH_WALLET_STATES >> 8);
    tlv[2] = (uint8_t)(TAG_FLASH_WALLET_STATES >> 16);
    tlv[3] = (uint8_t)(TAG_FLASH_WALLET_STATES >> 24);
    uint16_t index = 6;

    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_ID, sizeof(wallet->wallet_id), wallet->wallet_id);
    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_STATE, sizeof(wallet->state), &(wallet->state));
    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_CARD_STATE, sizeof(wallet->cards_states), &(wallet->cards_states));

    if(wallet->is_wallet_locked == true){
        fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_LOCKED, sizeof(wallet->is_wallet_locked), (uint8_t*)(&(wallet->is_wallet_locked)));
        serialize_pow(tlv, &index, &(wallet->challenge));
    }

    tlv[4] = index - 6;
    tlv[5] = (index - 6) >> 8 ;

    return index;

}

static uint16_t serialize_wallet_unlock_data(const Flash_Wallet* wallet, uint8_t* tlv){
    tlv[0] = (uint8_t)(TAG_FLASH_WALLET_UNLOCK_DATA);
    tlv[1] = (uint8_t)(TAG_FLASH_WALLET_UNLOCK_DATA >> 8);
    tlv[2] = (uint8_t)(TAG_FLASH_WALLET_UNLOCK_DATA >> 16);
    tlv[3] = (uint8_t)(TAG_FLASH_WALLET_UNLOCK_DATA >> 24);
    uint16_t index = 6;

    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_ID, sizeof(wallet->wallet_id), wallet->wallet_id);
    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_CHALLENGE_NONCE, POW_NONCE_SIZE, (uint8_t *) wallet->challenge.nonce);
    fill_flash_tlv(tlv, &index, TAG_FLASH_WALLET_CHALLENGE_TIME_LOCKED, sizeof(wallet->challenge.time_to_unlock_in_secs), (uint8_t *) (&(wallet->challenge.time_to_unlock_in_secs)));

    tlv[4] = index - 6;
    tlv[5] = (index - 6) >> 8 ;

    return index;
   
}


/**
 * @brief Helper function to extract values of Flash_Wallet from TLV. 
 *        Used to populate flash_struct when depricated tag TAG_FLASH_STRUCT 
 *        is found on flash
 * 
 * @param flash_wallet Pointer to Flash_Wallet instance to store the values
 * @param tlv TLV byte array
 * @param len Length of the stored Flash_Wallet in TLV (including all the tags and intermediate lengths). Note that this is not sizeof(Flash_Wallet).
 */
static void deserialize_wallet_metadata(Flash_Wallet* flash_wallet, const uint8_t* tlv, const uint16_t len) {

    uint16_t index = 0;

    while(index<len) { 
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch (tag) {
            case TAG_FLASH_WALLET_INFO: {
                memcpy(&(flash_wallet->wallet_info), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_NAME: {
                memcpy(&(flash_wallet->wallet_name), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_ID: {
                memcpy(flash_wallet->wallet_id, tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

/**
 * @brief Function to extract values of Flash_Struct from TLV. 
 *        Used to populate flash_struct when depricated tag TAG_FLASH_STRUCT 
 *        is found on flash
 * 
 * @param flash_struct Pointer to Flash_Struct instance to store the values
 * @param tlv TLV byte array
 */
static void deserialize_device_metadata(Flash_Struct *flash_struct, uint8_t *tlv)
{

    uint16_t index = 4; // First 4 bytes are the TAG_FLASH_STRUCT
    uint16_t len = tlv[index] + (tlv[index + 1] << 8) + 6;

    index += 2;

    while (index < len) {
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch (tag) {
            case TAG_FLASH_FAMILY_ID: {
                memcpy(flash_struct->family_id, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_COUNT: {
                memcpy(&(flash_struct->wallet_count), tlv + index + 2, size);
                break;
            }

            // TODO: Remove wallet list tag and replace with wallet id tag
            case TAG_FLASH_WALLET_LIST: {
                uint16_t offset = index + 2;
                for (uint8_t wallet_index = 0; wallet_index < MAX_WALLETS_ALLOWED; wallet_index++)
                {
                    if (tlv[offset++] == TAG_FLASH_WALLET)
                    {
                        uint16_t wallet_len = tlv[offset] + (tlv[offset + 1] << 8);
                        deserialize_wallet_metadata(&(flash_struct->wallets[wallet_index]), tlv + offset + 2, wallet_len);
                        offset += wallet_len + 2;
                    }
                }
                // TODO: ASSERT(offset == index + size + 2);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

static void deserialize_pow_data(Flash_Pow* flash_pow, const uint8_t* tlv, const uint16_t len) {
    
    uint16_t index = 0;   
    while(index<len) {
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch(tag) {
            case TAG_FLASH_WALLET_CHALLENGE_TARGET: {
                memcpy(flash_pow->target, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_RANDOM_NUMBER: {
                memcpy(flash_pow->random_number, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_CARD_LOCKED: {
                memcpy(&(flash_pow->card_locked), tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

static void deserialize_wallet_state(Flash_Wallet *flash_wallet, const uint8_t* tlv, const uint16_t len){
    uint16_t index = 0;

    while(index<len) { 
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch (tag) {
            case TAG_FLASH_WALLET_STATE: {
                memcpy(&(flash_wallet->state), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CARD_STATE: {
                memcpy(&(flash_wallet->cards_states), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_LOCKED: {
                memcpy(&(flash_wallet->is_wallet_locked), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE: {
                deserialize_pow_data(&(flash_wallet->challenge),tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

static void deserialize_device_settings(Flash_Struct* flash_struct, const uint8_t* tlv, const uint16_t len) {
    uint16_t index = 0;
    while(index<len) {
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch(tag) {
            case TAG_FLASH_DISPLAY_ROTATION: {
                memcpy(&(flash_struct->displayRotation), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_TOGGLE_PASSPHRASE: {
                memcpy(&(flash_struct->enable_passphrase), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_TOGGLE_LOGS: {
                memcpy(&(flash_struct->enable_log), tlv + index + 2, size);
                break;
            }
            
            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

static void deserialize_wallet_unlock_data(Flash_Pow* flash_pow, const uint8_t* tlv, const uint16_t len) {
    
    uint16_t index = 0;   
    while(index<len) {
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch(tag) {
            case TAG_FLASH_WALLET_CHALLENGE_NONCE: {
                memcpy(flash_pow->nonce, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_TIME_LOCKED: {
                memcpy(&(flash_pow->time_to_unlock_in_secs), tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

/**************************************************************************************************************************************************************/

/**
 * @brief (DEPRICATED)Helper function to extract values of Flash_Pow from TLV. 
 *        Used to populate flash_struct when depricated tag TAG_FLASH_STRUCT 
 *        is found on flash
 * 
 * @param flash_pow Pointer to Flash_Pow instance to store the values
 * @param tlv TLV byte array
 * @param len Length of the stored Flash_Pow in TLV (including all the tags and intermediate lengths). Note that this is not sizeof(Flash_Pow).
 */
static void deserialize_fs_pow(Flash_Pow* flash_pow, const uint8_t* tlv, const uint16_t len) {
    
    uint16_t index = 0;   
    while(index<len) {
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch(tag) {
            case TAG_FLASH_WALLET_CHALLENGE_TARGET: {
                memcpy(flash_pow->target, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_RANDOM_NUMBER: {
                memcpy(flash_pow->random_number, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_NONCE: {
                memcpy(flash_pow->nonce, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_CARD_LOCKED: {
                memcpy(&(flash_pow->card_locked), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE_TIME_LOCKED: {
                memcpy(&(flash_pow->time_to_unlock_in_secs), tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}

/**
 * @brief (DEPRICATED) Helper function to extract values of Flash_Wallet from TLV. 
 *        Used to populate flash_struct when depricated tag TAG_FLASH_STRUCT 
 *        is found on flash
 * 
 * @param flash_wallet Pointer to Flash_Wallet instance to store the values
 * @param tlv TLV byte array
 * @param len Length of the stored Flash_Wallet in TLV (including all the tags and intermediate lengths). Note that this is not sizeof(Flash_Wallet).
 */
static void deserialize_fs_wallet(Flash_Wallet* flash_wallet, const uint8_t* tlv, const uint16_t len) {

    uint16_t index = 0;

    while(index<len) { 
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch (tag) {
            case TAG_FLASH_WALLET_STATE: {
                memcpy(&(flash_wallet->state), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CARD_STATE: {
                memcpy(&(flash_wallet->cards_states), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_INFO: {
                memcpy(&(flash_wallet->wallet_info), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_NAME: {
                memcpy(&(flash_wallet->wallet_name), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_LOCKED: {
                memcpy(&(flash_wallet->is_wallet_locked), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_CHALLENGE: {
                deserialize_fs_pow(&(flash_wallet->challenge),tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_ID: {
                memcpy(flash_wallet->wallet_id, tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}


/**
 * @brief (DEPRICATED) Function to extract values of Flash_Struct from TLV. 
 *        Used to populate flash_struct when depricated tag TAG_FLASH_STRUCT 
 *        is found on flash
 * 
 * @param flash_struct Pointer to Flash_Struct instance to store the values
 * @param tlv TLV byte array
 */
static void deserialize_fs(Flash_Struct *flash_struct, uint8_t *tlv)
{

    uint16_t index = 4; // First 4 bytes are the TAG_FLASH_STRUCT
    uint16_t len = tlv[index] + (tlv[index + 1] << 8) + 6;

    index += 2;

    while (index < len) {
        Flash_tlv_tags tag = tlv[index++];
        uint16_t size = tlv[index] + (tlv[index + 1] << 8);

        switch (tag) {
            case TAG_FLASH_FAMILY_ID: {
                memcpy(flash_struct->family_id, tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_COUNT: {
                memcpy(&(flash_struct->wallet_count), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_WALLET_LIST: {
                uint16_t offset = index + 2;
                for (uint8_t wallet_index = 0; wallet_index < MAX_WALLETS_ALLOWED; wallet_index++)
                {
                    if (tlv[offset++] == TAG_FLASH_WALLET)
                    {
                        uint16_t wallet_len = tlv[offset] + (tlv[offset + 1] << 8);
                        deserialize_fs_wallet(&(flash_struct->wallets[wallet_index]), tlv + offset + 2, wallet_len);
                        offset += wallet_len + 2;
                    }
                }
                // TODO: ASSERT(offset == index + size + 2);
                break;
            }

            case TAG_FLASH_DISPLAY_ROTATION: {
                memcpy(&(flash_struct->displayRotation), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_TOGGLE_PASSPHRASE: {
                memcpy(&(flash_struct->enable_passphrase), tlv + index + 2, size);
                break;
            }

            case TAG_FLASH_TOGGLE_LOGS: {
                memcpy(&(flash_struct->enable_log), tlv + index + 2, size);
                break;
            }

            default: {
                break;
            }
        }
        index += (size + 2);
    }
}
