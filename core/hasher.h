#ifndef _HASHER_H
#define _HASHER_H

#if defined(CONFIG_PLATFORM_8711B)
#include <basic_types.h>
#endif

#include "iotw_parser_bin.h"

int32_t hasher_loop(int sock);
int32_t hasher_get_address(const char *addr, const char *port, uint8_t *mac, uint16_t model, uint32_t version);
uint32_t hasher_get_mined_blocks(void);
uint32_t hasher_get_ledgerseq(void);
uint32_t hasher_status(void);
uint32_t hasher_notification(void * msg, uint32_t len);
uint32_t hasher_bin_msg_reply(void * msg, uint32_t len);
uint32_t hasher_control_query(void * msg, uint32_t len);
uint32_t hasher_meta_data_query(void * msg, uint32_t len);
uint32_t hasher_ping(void * msg, uint32_t len);
uint32_t hasher_unknown(void * msg, uint32_t len);
uint32_t hasher_ledger_verify_ext(void * msg, uint32_t len);
uint32_t hasher_ledger_verify(void * msg, uint32_t len);
uint32_t hasher_block_verify(void * msg, uint32_t len);

#endif // _HASHER_H
