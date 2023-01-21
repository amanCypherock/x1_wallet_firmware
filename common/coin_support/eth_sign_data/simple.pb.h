/* Automatically generated nanopb header */
/* Generated by nanopb-0.4.6 */

#ifndef PB_SIMPLE_PB_H_INCLUDED
#define PB_SIMPLE_PB_H_INCLUDED
#include "pb.h"

#if PB_PROTO_HEADER_VERSION != 40
#error Regenerate this file with the current version of nanopb generator.
#endif

/* Enum definitions */
typedef enum _TypedDataStruct_TypedDataNode_Eip712DataType {
  TypedDataStruct_TypedDataNode_Eip712DataType_UINT    = 1,
  TypedDataStruct_TypedDataNode_Eip712DataType_INT     = 2,
  TypedDataStruct_TypedDataNode_Eip712DataType_BYTES   = 3,
  TypedDataStruct_TypedDataNode_Eip712DataType_STRING  = 4,
  TypedDataStruct_TypedDataNode_Eip712DataType_BOOL    = 5,
  TypedDataStruct_TypedDataNode_Eip712DataType_ADDRESS = 6,
  TypedDataStruct_TypedDataNode_Eip712DataType_ARRAY   = 7,
  TypedDataStruct_TypedDataNode_Eip712DataType_STRUCT  = 8
} TypedDataStruct_TypedDataNode_Eip712DataType;

typedef enum _MessageData_MessageType {
  MessageData_MessageType_ETH_SIGN        = 1,
  MessageData_MessageType_PERSONAL_SIGN   = 2,
  MessageData_MessageType_SIGN_TYPED_DATA = 3
} MessageData_MessageType;

/* Struct definitions */
typedef struct _KAryTree {
  int32_t value;
  char *name;
  pb_size_t children_count;
  struct _KAryTree *children;
  pb_bytes_array_t *data;
} KAryTree;

typedef struct _LinkedList {
  int32_t value;
  struct _LinkedList *next;
} LinkedList;

typedef struct _SimpleMessage {
  int32_t lucky_number;
  pb_size_t more_count;
  struct _SimpleMessage *more;
} SimpleMessage;

typedef struct _TypedDataStruct_TypedDataNode {
  char *name;
  TypedDataStruct_TypedDataNode_Eip712DataType type;
  uint32_t size;
  char *struct_name;
  pb_bytes_array_t *data;
  pb_bytes_array_t *type_hash;
  pb_size_t children_count;
  struct _TypedDataStruct_TypedDataNode *children;
} TypedDataStruct_TypedDataNode;

typedef struct _TypedDataStruct {
  TypedDataStruct_TypedDataNode domain;
  TypedDataStruct_TypedDataNode message;
} TypedDataStruct;

typedef struct _MessageData {
  MessageData_MessageType messageType;
  pb_bytes_array_t *data_bytes;
  bool has_eip712data;
  TypedDataStruct eip712data;
} MessageData;

/* Helper constants for enums */
#define _TypedDataStruct_TypedDataNode_Eip712DataType_MIN TypedDataStruct_TypedDataNode_Eip712DataType_UINT
#define _TypedDataStruct_TypedDataNode_Eip712DataType_MAX TypedDataStruct_TypedDataNode_Eip712DataType_STRUCT
#define _TypedDataStruct_TypedDataNode_Eip712DataType_ARRAYSIZE \
  ((TypedDataStruct_TypedDataNode_Eip712DataType)(TypedDataStruct_TypedDataNode_Eip712DataType_STRUCT + 1))

#define _MessageData_MessageType_MIN       MessageData_MessageType_ETH_SIGN
#define _MessageData_MessageType_MAX       MessageData_MessageType_SIGN_TYPED_DATA
#define _MessageData_MessageType_ARRAYSIZE ((MessageData_MessageType)(MessageData_MessageType_SIGN_TYPED_DATA + 1))

#ifdef __cplusplus
extern "C" {
#endif

/* Initializer values for message structs */
#define SimpleMessage_init_default \
  { 0, 0, NULL }
#define LinkedList_init_default \
  { 0, NULL }
#define KAryTree_init_default \
  { 0, NULL, 0, NULL, NULL }
#define TypedDataStruct_init_default \
  { TypedDataStruct_TypedDataNode_init_default, TypedDataStruct_TypedDataNode_init_default }
#define TypedDataStruct_TypedDataNode_init_default \
  { NULL, _TypedDataStruct_TypedDataNode_Eip712DataType_MIN, 0, NULL, NULL, NULL, 0, NULL }
#define MessageData_init_default \
  { _MessageData_MessageType_MIN, NULL, false, TypedDataStruct_init_default }
#define SimpleMessage_init_zero \
  { 0, 0, NULL }
#define LinkedList_init_zero \
  { 0, NULL }
#define KAryTree_init_zero \
  { 0, NULL, 0, NULL, NULL }
#define TypedDataStruct_init_zero \
  { TypedDataStruct_TypedDataNode_init_zero, TypedDataStruct_TypedDataNode_init_zero }
#define TypedDataStruct_TypedDataNode_init_zero \
  { NULL, _TypedDataStruct_TypedDataNode_Eip712DataType_MIN, 0, NULL, NULL, NULL, 0, NULL }
#define MessageData_init_zero \
  { _MessageData_MessageType_MIN, NULL, false, TypedDataStruct_init_zero }

/* Field tags (for use in manual encoding/decoding) */
#define KAryTree_value_tag                            1
#define KAryTree_name_tag                             2
#define KAryTree_children_tag                         3
#define KAryTree_data_tag                             4
#define LinkedList_value_tag                          1
#define LinkedList_next_tag                           2
#define SimpleMessage_lucky_number_tag                1
#define SimpleMessage_more_tag                        2
#define TypedDataStruct_TypedDataNode_name_tag        1
#define TypedDataStruct_TypedDataNode_type_tag        2
#define TypedDataStruct_TypedDataNode_size_tag        3
#define TypedDataStruct_TypedDataNode_struct_name_tag 4
#define TypedDataStruct_TypedDataNode_data_tag        5
#define TypedDataStruct_TypedDataNode_type_hash_tag   6
#define TypedDataStruct_TypedDataNode_children_tag    7
#define TypedDataStruct_domain_tag                    1
#define TypedDataStruct_message_tag                   2
#define MessageData_messageType_tag                   1
#define MessageData_data_bytes_tag                    2
#define MessageData_eip712data_tag                    3

/* Struct field encoding specification for nanopb */
#define SimpleMessage_FIELDLIST(X, a)            \
  X(a, STATIC, REQUIRED, INT32, lucky_number, 1) \
  X(a, POINTER, REPEATED, MESSAGE, more, 2)
#define SimpleMessage_CALLBACK     NULL
#define SimpleMessage_DEFAULT      NULL
#define SimpleMessage_more_MSGTYPE SimpleMessage

#define LinkedList_FIELDLIST(X, a)        \
  X(a, STATIC, REQUIRED, INT32, value, 1) \
  X(a, POINTER, OPTIONAL, MESSAGE, next, 2)
#define LinkedList_CALLBACK     NULL
#define LinkedList_DEFAULT      NULL
#define LinkedList_next_MSGTYPE LinkedList

#define KAryTree_FIELDLIST(X, a)                \
  X(a, STATIC, REQUIRED, INT32, value, 1)       \
  X(a, POINTER, REQUIRED, STRING, name, 2)      \
  X(a, POINTER, REPEATED, MESSAGE, children, 3) \
  X(a, POINTER, REQUIRED, BYTES, data, 4)
#define KAryTree_CALLBACK         NULL
#define KAryTree_DEFAULT          NULL
#define KAryTree_children_MSGTYPE KAryTree

#define TypedDataStruct_FIELDLIST(X, a)      \
  X(a, STATIC, REQUIRED, MESSAGE, domain, 1) \
  X(a, STATIC, REQUIRED, MESSAGE, message, 2)
#define TypedDataStruct_CALLBACK        NULL
#define TypedDataStruct_DEFAULT         NULL
#define TypedDataStruct_domain_MSGTYPE  TypedDataStruct_TypedDataNode
#define TypedDataStruct_message_MSGTYPE TypedDataStruct_TypedDataNode

#define TypedDataStruct_TypedDataNode_FIELDLIST(X, a) \
  X(a, POINTER, REQUIRED, STRING, name, 1)            \
  X(a, STATIC, REQUIRED, UENUM, type, 2)              \
  X(a, STATIC, REQUIRED, UINT32, size, 3)             \
  X(a, POINTER, REQUIRED, STRING, struct_name, 4)     \
  X(a, POINTER, OPTIONAL, BYTES, data, 5)             \
  X(a, POINTER, OPTIONAL, BYTES, type_hash, 6)        \
  X(a, POINTER, REPEATED, MESSAGE, children, 7)
#define TypedDataStruct_TypedDataNode_CALLBACK         NULL
#define TypedDataStruct_TypedDataNode_DEFAULT          (const pb_byte_t *)"\x10\x01\x00"
#define TypedDataStruct_TypedDataNode_children_MSGTYPE TypedDataStruct_TypedDataNode

#define MessageData_FIELDLIST(X, a)             \
  X(a, STATIC, REQUIRED, UENUM, messageType, 1) \
  X(a, POINTER, OPTIONAL, BYTES, data_bytes, 2) \
  X(a, STATIC, OPTIONAL, MESSAGE, eip712data, 3)
#define MessageData_CALLBACK           NULL
#define MessageData_DEFAULT            (const pb_byte_t *)"\x08\x01\x00"
#define MessageData_eip712data_MSGTYPE TypedDataStruct

extern const pb_msgdesc_t SimpleMessage_msg;
extern const pb_msgdesc_t LinkedList_msg;
extern const pb_msgdesc_t KAryTree_msg;
extern const pb_msgdesc_t TypedDataStruct_msg;
extern const pb_msgdesc_t TypedDataStruct_TypedDataNode_msg;
extern const pb_msgdesc_t MessageData_msg;

/* Defines for backwards compatibility with code written before nanopb-0.4.0 */
#define SimpleMessage_fields                 &SimpleMessage_msg
#define LinkedList_fields                    &LinkedList_msg
#define KAryTree_fields                      &KAryTree_msg
#define TypedDataStruct_fields               &TypedDataStruct_msg
#define TypedDataStruct_TypedDataNode_fields &TypedDataStruct_TypedDataNode_msg
#define MessageData_fields                   &MessageData_msg

/* Maximum encoded size of messages (where known) */
/* SimpleMessage_size depends on runtime parameters */
/* LinkedList_size depends on runtime parameters */
/* KAryTree_size depends on runtime parameters */
/* TypedDataStruct_size depends on runtime parameters */
/* TypedDataStruct_TypedDataNode_size depends on runtime parameters */
/* MessageData_size depends on runtime parameters */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
