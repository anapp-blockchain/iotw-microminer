#if defined(CONFIG_PLATFORM_8711B)
#include <arm_math.h>
#define __builtin_clz __CLZ
#include "FreeRTOS.h"
#include "task.h"
#endif
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if !defined(CONFIG_PLATFORM_8711B)
#include <unistd.h>
#include <sys/types.h>
#endif
#include <ctype.h>
#include <stdarg.h>

#if __GNUC__ > 3
#include <stdint.h>
#include <stdbool.h>
#else
#define true 1
#endif

#include "hasher.h"
#include "logger.h"
#include "keys.h"
#include "mm_socks.h"
#include "events.h"
#include "iotw.h"
#include "arch_generic.h"
#include "miner.h"
#include "dev_control.h"
#include "iotwTools.h"
#include "IotwBinMessage.h"
#include "IotwBinSerialServerMessage.h"
#include "IotwDeviceModel.h"
#include "uECC.h"
#include "data_chunk.h"

#include "crc16.h"

#if defined(__XTENSA__)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "iotw_parser_bin.h"
#if !defined(ESP8266_SDK_VERSION_2)
#include "esp_task_wdt.h"
#endif
#endif

static const char *TAG  = "hash";

#define BLOCK_BUF_SIZE 1024*4

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#pragma pack(push, 1)
typedef struct {
	uint32_t id;
	uint32_t len;
	uint32_t nameid;
	uint16_t state;
} switch_t;
#pragma pack(pop)

static void dump_hex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

#if defined(ESP8266_SDK_VERSION_2)
STORE_ATTR
#endif
uint8_t block_buf[BLOCK_BUF_SIZE];

static uint32_t ledger_seq;
static uint32_t mined_blocks = 0;
static uint32_t internal_status = 0;

static uint32_t bswap32(uint32_t num) {

	uint32_t swapped = ((num>>24)&0xff) | // move byte 3 to byte 0
			((num<<8)&0xff0000) | // move byte 1 to byte 2
			((num>>8)&0xff00) | // move byte 2 to byte 1
			((num<<24)&0xff000000); // byte 0 to byte 3

	return swapped;
}

static void iotw_reverse_bytes(uint8_t *d, uint8_t *s, uint32_t size) 
{
	uint32_t i;
	for (i = 0 ; i < size ; i++) {
		d[i] = s[size - 1 - i];
	}
}

uint32_t hasher_status(void)
{
	return internal_status;
}

uint32_t hasher_get_ledgerseq(void)
{
	return ledger_seq;
}

uint32_t hasher_get_mined_blocks(void)
{
	return mined_blocks;
}

void hasher_print_hash(uint8_t *hash)
{
	char hashHex[65];
	memset(hashHex, 0, 65);
	iotw_to_hex((uint8_t *)hashHex, hash, 32);
	DBG_LOGI(TAG, "HASH: %s", hashHex);
}

struct IotwBinBlockVerifyReply msgBlockVerifyReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_BlockVerifyReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_block_verify(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	msgBlockVerifyReply.theHeader.theId = msg_ptr->theId;

	int size_to_hash = msg_ptr->len - sizeof(struct IotwBinBlockVerifyQuery);

	iotw_sha3_256_ctx ctx;

	iotw_sha3_256_stream_init(&ctx);

	DBG_LOGI(TAG, "Hashing block of size %d", size_to_hash);

	event_set(EVENT_GROUP_HASHER, HASHER_EVENT_HASHING);

#if __x86_64__
	memcpy(block_buf, (uint8_t *)((uint64_t)msg_ptr->data + sizeof(msgBlockVerifyReply)), size_to_hash);
#else
	memcpy(block_buf, (uint8_t *)((uint32_t)msg_ptr->data + sizeof(msgBlockVerifyReply)), size_to_hash);
#endif

	iotw_sha3_256_stream_update(&ctx, block_buf, size_to_hash);

	iotw_sha3_256_stream_final(&ctx, (uint8_t *)&msgBlockVerifyReply.theHash);
	hasher_print_hash((uint8_t *)&msgBlockVerifyReply.theHash);

	uECC_sign(keys_get_private_key(),
		(uint8_t *)&msgBlockVerifyReply.theHash, sizeof(msgBlockVerifyReply.theHash),
		(uint8_t *)&msgBlockVerifyReply.theSignature, uECC_secp256k1());

	if (iotw_send_bin(msg_ptr->sock,
		PARSER_MSG_ENCRYPTED_1_FLAG,
		(void *)&msgBlockVerifyReply,
		sizeof(msgBlockVerifyReply),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "hasher_block_verify - send failed");
		return -1;
	}

	if(msg_ptr->data)
		free(msg_ptr->data);

	mined_blocks++;
	return 0;
}

struct IotwBinLedgerVerifyQuery msgLedgerVerifyQuery __attribute__ ((aligned (4)));

struct IotwBinLedgerVerifyReply msgLedgerVerifyReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_LedgerVerifyReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_ledger_verify(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	msgLedgerVerifyReply.theHeader.theId = msg_ptr->theId;

	DBG_LOGI(TAG, "Hashing Ledger");
	event_set(EVENT_GROUP_HASHER, HASHER_EVENT_HASHING);

	memcpy((uint8_t *)&msgLedgerVerifyQuery, (uint8_t *)msg_ptr->data, sizeof(msgLedgerVerifyQuery));

	ledger_seq = msgLedgerVerifyQuery.theLedgerSeq;

	DBG_LOGI(TAG, "LedgerSeq: %08x", ledger_seq);

	msgLedgerVerifyReply.theLedgerSeq = msgLedgerVerifyQuery.theLedgerSeq;

	msgLedgerVerifyReply.theNonce = arch_random();

	iotw_sha3_256_ctx ctx;

	iotw_sha3_256_stream_init(&ctx);

	iotw_sha3_256_stream_update(&ctx, &msgLedgerVerifyReply.theLedgerSeq, sizeof(msgLedgerVerifyReply.theLedgerSeq));
	iotw_sha3_256_stream_update(&ctx, &msgLedgerVerifyReply.theNonce, sizeof(msgLedgerVerifyReply.theNonce));

	iotw_sha3_256_stream_final(&ctx, (uint8_t *)&msgLedgerVerifyReply.theHash);
	hasher_print_hash((uint8_t *)&msgLedgerVerifyReply.theHash);

	uECC_sign(keys_get_private_key(),
		(uint8_t *)&msgLedgerVerifyReply.theHash, sizeof(msgLedgerVerifyReply.theHash),
		(uint8_t *)&msgLedgerVerifyReply.theSignature, uECC_secp256k1());

	if (iotw_send_bin(msg_ptr->sock,
		PARSER_MSG_ENCRYPTED_1_FLAG,
		(void *)&msgLedgerVerifyReply,
		sizeof(msgLedgerVerifyReply),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "hasher_ledger_verify - send failed");
		return -1;
	}

	if(msg_ptr->data)
		free(msg_ptr->data);

	mined_blocks++;
	return 0;
}

struct IotwBinLedgerVerifyExtQuery msgLedgerVerifyExtQuery __attribute__ ((aligned (4)));

struct IotwBinLedgerVerifyExtReply msgLedgerVerifyExtReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_LedgerVerifyExtReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_ledger_verify_ext(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;
	uint32_t size = msg_ptr->len;
	uint8_t * data = (uint8_t *)msg_ptr->data;

	msgLedgerVerifyExtReply.theHeader.theId = msg_ptr->theId;

	DBG_LOGI(TAG, "Hashing Ledger");
	event_set(EVENT_GROUP_HASHER, HASHER_EVENT_HASHING);

	memcpy((uint8_t *)&msgLedgerVerifyExtQuery, (uint8_t *)msg_ptr->data, sizeof(msgLedgerVerifyExtQuery));

	int size_to_hash = msgLedgerVerifyExtQuery.theBlockLength;

	ledger_seq = msgLedgerVerifyExtQuery.theLedgerSeq;
	DBG_LOGI(TAG, "LedgerSeq: %08x", ledger_seq);


	if (size_to_hash > BLOCK_BUF_SIZE) {
		DBG_LOGE(TAG, "Block size too big: %d", size_to_hash);
		return -1;
	}

	DBG_LOGI(TAG, "Hashing block of size %d", size_to_hash);
	event_set(EVENT_GROUP_HASHER, HASHER_EVENT_HASHING);

#if __x86_64__
	memcpy(block_buf, (uint8_t *)((uint64_t)data + sizeof(msgLedgerVerifyExtQuery)), size_to_hash);
#else
	memcpy(block_buf, (uint8_t *)((uint32_t)data + sizeof(msgLedgerVerifyExtQuery)), size_to_hash);
#endif

	if (size - sizeof(msgLedgerVerifyExtQuery) - 2 != size_to_hash) {
		DBG_LOGE(TAG, "Didnt receive whole block to hash %d (%d)", size, size_to_hash);
		return -1;
	}

	uint32_t *nonce = (uint32_t *) (&block_buf[msgLedgerVerifyExtQuery.theNonceOffset]);

	int32_t max_lz = 0;
	uint32_t max_nonce =0;
	uint32_t i;
	uint32_t elapsed_time = arch_get_ms();
	uint8_t   hash1[32];
	uint8_t   hash2[32];

	for(i = msgLedgerVerifyExtQuery.theNonceBegin ; i <= msgLedgerVerifyExtQuery.theNonceEnd ; i++) {
		*nonce = i;

		if (msgLedgerVerifyExtQuery.theFlags == IotwBinLedgerVerifyExtQueryFlag_Hash_2Sha256R) {
			DBG_LOGI(TAG, "Calculating: 2SHA256R");
			iotw_sha2_256(hash1, block_buf, size_to_hash);
			iotw_sha2_256(hash2, hash1, sizeof(hash2));
			iotw_reverse_bytes(hash1, hash2, sizeof(hash1));
			hasher_print_hash(hash1);
		} else {
			iotw_sha3_256(hash1, block_buf, size_to_hash);
		}

		int32_t lz = __builtin_clz(bswap32(*(uint32_t *)hash1));

		if (lz > max_lz) {
			max_lz = lz;
			max_nonce = i;
		}
	}
	elapsed_time = arch_get_ms() - elapsed_time;

	*nonce = max_nonce;
	msgLedgerVerifyExtReply.theNonce = max_nonce;
	DBG_LOGI(TAG, "NONCE: %d MAX_CLZ: %d", max_nonce, max_lz);

	if (msgLedgerVerifyExtQuery.theFlags == IotwBinLedgerVerifyExtQueryFlag_Hash_2Sha256R) {
		DBG_LOGI(TAG, "Calculating: 2SHA256R");
		iotw_sha2_256(hash1, block_buf, size_to_hash);
		iotw_sha2_256(hash2, hash1, sizeof(hash1));
		iotw_reverse_bytes((uint8_t *)&msgLedgerVerifyExtReply.theHash, hash2, sizeof(hash2));
	} else {
		DBG_LOGI(TAG, "Calculating: SHA3");
		iotw_sha3_256((uint8_t *)&msgLedgerVerifyExtReply.theHash, block_buf, size_to_hash);
	}

	hasher_print_hash((uint8_t *)&msgLedgerVerifyExtReply.theHash);

	uECC_sign(keys_get_private_key(),
		(uint8_t *)&msgLedgerVerifyExtReply.theHash, sizeof(msgLedgerVerifyExtReply.theHash),
		(uint8_t *)&msgLedgerVerifyExtReply.theSignature, uECC_secp256k1());

	msgLedgerVerifyExtReply.theLedgerSeq = msgLedgerVerifyExtQuery.theLedgerSeq;

	msgLedgerVerifyExtReply.theElapsedTime = elapsed_time;

	if (iotw_send_bin(msg_ptr->sock,
		0x04 /* change for dynamic*/,
		(void *)&msgLedgerVerifyExtReply,
		sizeof(struct IotwBinLedgerVerifyExtReply),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "Sending IotwBinLedgerVerifyReply failed");
		return -1;
	}

	if(msg_ptr->data)
		free(msg_ptr->data);

	mined_blocks++;
	DBG_LOGI(TAG, "BLOCK HASH COUNT: %d", mined_blocks);
	return 0;
}

struct IotwBinErrorReply msgErrorReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ErrorReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_unknown(void * msg, uint32_t len)
{
	struct IotwBinMessageHeader bin_msg;

	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	msgErrorReply.theHeader.theId = msg_ptr->theId;

	DBG_LOGI(TAG, "Receiving Unknown Command");

	memcpy((uint8_t *)&bin_msg, (uint8_t *)msg_ptr->data, sizeof(bin_msg));

	DBG_LOGE(TAG, "Processing Unknown Command: %04x (%04x) size: %d", bin_msg.theCommand, bin_msg.theVersion, msg_ptr->len);

	msgErrorReply.theQueryHeader.theCommand = bin_msg.theCommand;
	msgErrorReply.theQueryHeader.theVersion = bin_msg.theVersion;
	msgErrorReply.theErrorCode = IotwBinErrorCode_UnknownCommand;

	if (iotw_send_bin(msg_ptr->sock,
		0x04,
		(void *)&msgErrorReply,
		sizeof(msgErrorReply),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "hasher_ledger_verify - send failed");
		return -1;
	}

	if(msg_ptr->data)
		free(msg_ptr->data);

	return 0;
}

struct IotwBinPingQuery msgPingQuery __attribute__ ((aligned (4)));

struct IotwBinPingReply msgPingReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_PingReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_ping(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	msgPingReply.theHeader.theId = msg_ptr->theId;

	DBG_LOGI(TAG, "Receiving Ping");

	memcpy((uint8_t *)&msgPingQuery, (uint8_t *)msg_ptr->data, sizeof(msgPingQuery));

	DBG_LOGI(TAG, "Received Ping: %08x %08x", msgPingQuery.theTime.theDays, msgPingQuery.theTime.theMsecs);

	msgPingReply.theTime = msgPingQuery.theTime;

	if (iotw_send_bin(msg_ptr->sock,
		PARSER_MSG_ENCRYPTED_1_FLAG,
		(void *)&msgPingReply,
		sizeof(msgPingReply),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "hasher_ping - send failed");
		return -1;
	}

	if(msg_ptr->data)
		free(msg_ptr->data);

	return 0;
}

struct IotwBinControlQuery msgControlQuery __attribute__ ((aligned (4)));

uint32_t hasher_control_query(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	memcpy((uint8_t *)&msgControlQuery, (uint8_t *)msg_ptr->data, sizeof(msgControlQuery));

	DBG_LOGI(TAG, "Received Control Query: len: %d", msgControlQuery.theBlockLength);

	int ret;
	int32_t remaining_length = (int32_t) msg_ptr->len - sizeof(struct IotwBinControlQuery) -2;

	ret = dc_process_control(msg_ptr->sock, (uint8_t *)msg_ptr->data + sizeof(struct IotwBinControlQuery), remaining_length, msg_ptr->theId);
	if (ret < 0) {
		DBG_LOGE(TAG, "Failed to recive chunk");
		free(msg_ptr->data);
		return -1;
	}

	if(msg_ptr->data)
	free(msg_ptr->data);

	return 0;
}

struct IotwBinMetaDataQuery msgMetaDataQuery __attribute__ ((aligned (4)));

struct IotwBinMetaDataReply msgMetaDataReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_MetaDataReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_meta_data_query(void * msg, uint32_t len)
{
	int32_t ret = 0;

	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	msgMetaDataReply.theHeader.theId = msg_ptr->theId;

	memcpy((uint8_t *)&msgMetaDataQuery, (uint8_t *)msg_ptr->data, sizeof(msgMetaDataQuery));

	DBG_LOGI(TAG, "Received Meta Data Query");

	switch(msgMetaDataQuery.theDataChunkId){

	case IOTW_DATA_CHUNK_META_DATA:
	{
		DBG_LOGW(TAG, "META QUERY --> All");

		// create SWTC meta param
		IotwDataChunkBuilder_t * builder_switch = 0;
		IotwDataChunkBuilder_init(&builder_switch);
		BUILDER_ADD_DATA(&builder_switch, uint32_t, IotwBinDataMetaParameter_Int32);
		IotwDataChunkBuilder_add_string(&builder_switch, (uint8_t*)"", 1);
		IotwDataChunkBuilder_pack(&builder_switch, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		// create STTE reply chunk
		IotwDataChunkBuilder_t * builder_meta_swtc = 0;
		IotwDataChunkBuilder_init(&builder_meta_swtc);
		BUILDER_ADD_DATA(&builder_meta_swtc, uint32_t, IOTW_CTRL_CHUNK_SWITCH);
		IotwDataChunkBuilder_add_data(&builder_meta_swtc, builder_switch->data, builder_switch->len);
		IotwDataChunkBuilder_pack(&builder_meta_swtc, IOTW_DATA_CHUNK_META_DATA);

		IotwDataChunkBuilder_t * builder_r = 0;
		IotwDataChunkBuilder_init(&builder_r);
		BUILDER_ADD_DATA(&builder_r, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_r, (uint8_t*)"r", 2);
		IotwDataChunkBuilder_pack(&builder_r, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		IotwDataChunkBuilder_t * builder_g = 0;
		IotwDataChunkBuilder_init(&builder_g);
		BUILDER_ADD_DATA(&builder_g, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_g, (uint8_t*)"g", 2);
		IotwDataChunkBuilder_pack(&builder_g, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		IotwDataChunkBuilder_t * builder_b = 0;
		IotwDataChunkBuilder_init(&builder_b);
		BUILDER_ADD_DATA(&builder_b, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_b, (uint8_t*)"b", 2);
		IotwDataChunkBuilder_pack(&builder_b, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		IotwDataChunkBuilder_t * builder_w = 0;
		IotwDataChunkBuilder_init(&builder_w);
		BUILDER_ADD_DATA(&builder_w, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_w, (uint8_t*)"w", 2);
		IotwDataChunkBuilder_pack(&builder_w, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		// create STTE reply chunk
		IotwDataChunkBuilder_t * builder_meta_rgbw = 0;
		IotwDataChunkBuilder_init(&builder_meta_rgbw);
		BUILDER_ADD_DATA(&builder_meta_rgbw, uint32_t, IOTW_CTRL_CHUNK_RGBW);
		IotwDataChunkBuilder_add_data(&builder_meta_rgbw, builder_r->data, builder_r->len);
		IotwDataChunkBuilder_add_data(&builder_meta_rgbw, builder_g->data, builder_g->len);
		IotwDataChunkBuilder_add_data(&builder_meta_rgbw, builder_b->data, builder_b->len);
		IotwDataChunkBuilder_add_data(&builder_meta_rgbw, builder_w->data, builder_w->len);
		IotwDataChunkBuilder_pack(&builder_meta_rgbw, IOTW_DATA_CHUNK_META_DATA);

		msgMetaDataReply.theBlockLength = builder_meta_swtc->len + builder_meta_rgbw->len;

		uint8_t * theMainMetaChunk = (uint8_t*)malloc(msgMetaDataReply.theBlockLength);
		if(theMainMetaChunk == NULL){
			DBG_LOGE(TAG, "Main meta chunk memory allocation error.");
			return -1;
		}
		memcpy(theMainMetaChunk, builder_meta_swtc->data, builder_meta_swtc->len);
		memcpy(&theMainMetaChunk[builder_meta_swtc->len], builder_meta_rgbw->data, builder_meta_rgbw->len);

		if (iotw_send_bin(msg_ptr->sock,
			PARSER_MSG_ENCRYPTED_1_FLAG,
			(void *)&msgMetaDataReply,
			sizeof(msgMetaDataReply),
			theMainMetaChunk,
			msgMetaDataReply.theBlockLength,
			(void *)NULL) < 0)
		{
			DBG_LOGE(TAG, "hasher_control_query - send failed");
			ret = -1;
		}

		free(theMainMetaChunk);
		IotwDataChunkBuilder_free(&builder_switch);
		IotwDataChunkBuilder_free(&builder_r);
		IotwDataChunkBuilder_free(&builder_g);
		IotwDataChunkBuilder_free(&builder_b);
		IotwDataChunkBuilder_free(&builder_w);
		IotwDataChunkBuilder_free(&builder_meta_swtc);
		IotwDataChunkBuilder_free(&builder_meta_rgbw);
		break;
	}
	case IOTW_CTRL_CHUNK_SWITCH:
	{
		DBG_LOGW(TAG, "META QUERY --> SWTC");

		// create SWTC meta param
		IotwDataChunkBuilder_t * builder_switch = 0;
		IotwDataChunkBuilder_init(&builder_switch);
		BUILDER_ADD_DATA(&builder_switch, uint32_t, IotwBinDataMetaParameter_Int32);
		IotwDataChunkBuilder_add_string(&builder_switch, (uint8_t*)"", 1);
		IotwDataChunkBuilder_pack(&builder_switch, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		// create STTE reply chunk
		IotwDataChunkBuilder_t * builder_meta = 0;
		IotwDataChunkBuilder_init(&builder_meta);
		BUILDER_ADD_DATA(&builder_meta, uint32_t, IOTW_CTRL_CHUNK_SWITCH);
		IotwDataChunkBuilder_add_data(&builder_meta, builder_switch->data, builder_switch->len);
		IotwDataChunkBuilder_pack(&builder_meta, IOTW_DATA_CHUNK_META_DATA);

		msgMetaDataReply.theBlockLength = builder_meta->len;

		if (iotw_send_bin(msg_ptr->sock,
			PARSER_MSG_ENCRYPTED_1_FLAG,
			(void *)&msgMetaDataReply,
			sizeof(msgMetaDataReply),
			builder_meta->data,
			builder_meta->len,
			(void *)NULL) < 0)
		{
			DBG_LOGE(TAG, "hasher_control_query - send failed");
			ret = -1;
		}

		IotwDataChunkBuilder_free(&builder_switch);
		IotwDataChunkBuilder_free(&builder_meta);
		break;
	}
	case IOTW_CTRL_CHUNK_RGBW:
	{
		DBG_LOGW(TAG, "META QUERY --> RGBW");

		IotwDataChunkBuilder_t * builder_r = 0;
		IotwDataChunkBuilder_init(&builder_r);
		BUILDER_ADD_DATA(&builder_r, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_r, (uint8_t*)"r", 2);
		IotwDataChunkBuilder_pack(&builder_r, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		IotwDataChunkBuilder_t * builder_g = 0;
		IotwDataChunkBuilder_init(&builder_g);
		BUILDER_ADD_DATA(&builder_g, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_g, (uint8_t*)"g", 2);
		IotwDataChunkBuilder_pack(&builder_g, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		IotwDataChunkBuilder_t * builder_b = 0;
		IotwDataChunkBuilder_init(&builder_b);
		BUILDER_ADD_DATA(&builder_b, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_b, (uint8_t*)"b", 2);
		IotwDataChunkBuilder_pack(&builder_b, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		IotwDataChunkBuilder_t * builder_w = 0;
		IotwDataChunkBuilder_init(&builder_w);
		BUILDER_ADD_DATA(&builder_w, uint32_t, IotwBinDataMetaParameter_UInt8_N);
		IotwDataChunkBuilder_add_string(&builder_w, (uint8_t*)"w", 2);
		IotwDataChunkBuilder_pack(&builder_w, IOTW_DATA_CHUNK_META_DATA_PARAMETER);

		// create STTE reply chunk
		IotwDataChunkBuilder_t * builder_meta = 0;
		IotwDataChunkBuilder_init(&builder_meta);
		BUILDER_ADD_DATA(&builder_meta, uint32_t, IOTW_CTRL_CHUNK_RGBW);
		IotwDataChunkBuilder_add_data(&builder_meta, builder_r->data, builder_r->len);
		IotwDataChunkBuilder_add_data(&builder_meta, builder_g->data, builder_g->len);
		IotwDataChunkBuilder_add_data(&builder_meta, builder_b->data, builder_b->len);
		IotwDataChunkBuilder_add_data(&builder_meta, builder_w->data, builder_w->len);
		IotwDataChunkBuilder_pack(&builder_meta, IOTW_DATA_CHUNK_META_DATA);

		msgMetaDataReply.theBlockLength = builder_meta->len;

		if (iotw_send_bin(msg_ptr->sock,
			PARSER_MSG_ENCRYPTED_1_FLAG,
			(void *)&msgMetaDataReply,
			sizeof(msgMetaDataReply),
			builder_meta->data,
			builder_meta->len,
			(void *)NULL) < 0)
		{
			DBG_LOGE(TAG, "hasher_control_query - send failed");
			ret = -1;
		}

		IotwDataChunkBuilder_free(&builder_r);
		IotwDataChunkBuilder_free(&builder_g);
		IotwDataChunkBuilder_free(&builder_b);
		IotwDataChunkBuilder_free(&builder_w);
		IotwDataChunkBuilder_free(&builder_meta);
		break;
	}
	default:
	{
		DBG_LOGE(TAG, "Unknown Meta Data Query");
	}
	}

	if(msg_ptr->data)
	free(msg_ptr->data);

	return ret;
}

struct IotwBinNotificationQuery msgNotificationQuery __attribute__ ((aligned (4)));

struct IotwBinNotificationReply msgNotificationReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_NotificationReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_notification(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	msgNotificationReply.theHeader.theId = msg_ptr->theId;

	memcpy((uint8_t *)&msgNotificationQuery, (uint8_t *)msg_ptr->data, sizeof(msgNotificationQuery));

	DBG_LOGI(TAG, "Received Notification: %08x", msgNotificationQuery.theType);
  
	internal_status = msgNotificationQuery.theType;
	switch (msgNotificationQuery.theType) {
	case IotwBinNotificationType_RewardAccountAssigned:
		event_set(EVENT_GROUP_HASHER, HASHER_EVENT_MINING);
		break;
	case IotwBinNotificationType_RewardAccountUnassigned:
		event_clr(EVENT_GROUP_HASHER, HASHER_EVENT_MINING);
		break;
	case IotwBinNotificationType_ForcedUpdate:
		event_set(EVENT_GROUP_SERVICE, SERVICE_EVENT_FORCE_OTA);
		break;
	case IotwBinNotificationType_ForcedReset:
		arch_restart();
		break;
	case IotwBinNotificationType_ForcedWifiReset:
		DBG_LOGI(TAG, "Received Force WiFi Reset");
		event_set(EVENT_GROUP_SERVICE, SERVICE_EVENT_RESET_WIFI);
		break;
	case IotwBinNotificationType_ForcedNetChange:
		miner_set_env(msgNotificationQuery.theArg);
		return -1;
		break;
	default:
		DBG_LOGE(TAG, "Unknown Notification type: %d", msgNotificationQuery.theType);
		break;
	}

	if (iotw_send_bin(msg_ptr->sock,
		PARSER_MSG_ENCRYPTED_1_FLAG,
		(void *)&msgNotificationReply,
		sizeof(msgNotificationReply),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "hasher_notification - send failed");
		return -1;
	}

	if(msg_ptr->data)
		free(msg_ptr->data);

	return 0;
}

struct IotwBinClientJoinReply msgJoinReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ClientJoinReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

struct IotwBinControlQuery queryMsg __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ControlQuery,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

struct IotwBinControlReply replyQueryMsg __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ControlReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

struct IotwBinDataReply replyDataMsg __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_DataReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
};

uint32_t hasher_bin_msg_reply(void * msg, uint32_t len)
{
	bin_msg_t * msg_ptr = (bin_msg_t *)msg;

	switch(msg_ptr->theCommand){
	sleep_ms(10);

	case IotwBinMessage_ClientJoinReply:
	{
		memcpy((uint8_t *)&msgJoinReply, (uint8_t *)msg_ptr->data, sizeof(msgJoinReply));

		event_set(EVENT_GROUP_HASHER, HASHER_EVENT_CONNECTED);

		if (msgJoinReply.theStatus & IotwBinClientJoinQueryStatus_NoRewardAccount) {
			event_clr(EVENT_GROUP_HASHER, HASHER_EVENT_MINING);
		} else {
			event_set(EVENT_GROUP_HASHER, HASHER_EVENT_MINING);
		}
		uint16_t *ipv6 = (uint16_t *)&msgJoinReply.thePublicIPv6;
		uint8_t *ipv4 = (uint8_t *)&msgJoinReply.thePublicIPv6;
		ipv4 += 12;
		if (ipv6[0] == 0x0000 && ipv6[5] == 0xffff) {
			DBG_LOGI(TAG, "IPv6: %04x:%04x:%04x:%04x:%04x:%04x:%d.%d.%d.%d", ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
		} else {
			DBG_LOGI(TAG, "IPv6: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x", ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7])
		}
		sock_keepalive(msg_ptr->sock, true);

		if (msgJoinReply.theStatus & IotwBinClientJoinQueryStatus_NoGeoLocation) {
			DBG_LOGW(TAG, "GEO Requested.");
			arch_geo(msg_ptr->sock);
		}
		sleep_ms(10);

		int32_t nameId_ver = IOTW_CTRL_CHUNK_NAMEID_NONE,
		theFirmware = arch_get_firmware(),
		theFunctionSet = arch_get_function_set();

		IotwDataChunkBuilder_t * builder_ver = 0;
		IotwDataChunkBuilder_init(&builder_ver);
		BUILDER_ADD_DATA(&builder_ver, uint32_t, nameId_ver);
		BUILDER_ADD_DATA(&builder_ver, uint32_t, theFirmware);
		BUILDER_ADD_DATA(&builder_ver, uint32_t, theFunctionSet);
		IotwDataChunkBuilder_pack(&builder_ver, IOTW_CTRL_CHUNK_DEVICE_VER);

		queryMsg.theBlockLength = builder_ver->len;

		sleep_ms(10);

		if (iotw_send_bin(msg_ptr->sock,
			PARSER_MSG_ENCRYPTED_1_FLAG,
			(void *)&queryMsg,
			sizeof(queryMsg),
			builder_ver->data,
			builder_ver->len,
			(void *)NULL) < 0)
		{
			DBG_LOGE(TAG, "hasher_control_query - send failed");
			return -1;
		}

		IotwDataChunkBuilder_free(&builder_ver);

		DBG_LOGI(TAG, "#### READY FOR HASHING ####");

		event_clr(EVENT_GROUP_HASHER, HASHER_EVENT_HASHING);
		break;
	}
	case IotwBinMessage_ControlReply:
	{
		memcpy((uint8_t *)&replyQueryMsg, (uint8_t *)msg_ptr->data, sizeof(replyQueryMsg));
		DBG_LOGI(TAG, "Control Reply received len: %i", replyQueryMsg.theBlockLength);

		if(replyQueryMsg.theBlockLength){
#define PROCESS_CTRL_MAX_BUFFER_LEN 256
			IotwDataChunkParser_t * parser = 0;
			struct IotwBinDataChunk replyChunk;

			IotwDataChunkParser_init(&parser, (uint8_t *)&msg_ptr->data[sizeof(replyQueryMsg)], msg_ptr->len, NULL);
			replyChunk = IotwDataChunkParser_next(&parser);

			switch(replyChunk.theId)
			{
			case IOTW_CTRL_CHUNK_GEO_KEY:
			{
				uint8_t str[128] = {0,};
				uint32_t nameId;
				PARSER_NEXT_DATA(&parser, uint32_t, &nameId);
				IotwDataChunkParser_nextData_string(&parser, str, sizeof(str));
				DBG_LOGD(TAG, "API KEY Received");

				arch_nvs_write(api_key_google, str, strlen((char*)str)+1);
				arch_geo(msg_ptr->sock);
				break;
			}
			default:
			{
				DBG_LOGE(TAG, "Unknown control reply");
			}
			}

			IotwDataChunkParser_free(&parser);
		}
		break;
	}
	case IotwBinMessage_DataReply:
	{
		memcpy((uint8_t *)&replyDataMsg, (uint8_t *)msg_ptr->data, sizeof(replyDataMsg));
		DBG_LOGI(TAG, "Data Reply received.");
		break;
	}
	default:
	{
		DBG_LOGW(TAG, "Unknown Bin Message reply: %i", msg_ptr->theCommand);
	}
	}

	if(msg_ptr->data)
		free(msg_ptr->data);
	return 0;
}

void hasher_print_server_reply(uint8_t *server_reply, uint32_t len)
{
}


uint8_t buff[512];
extern uint8_t key[];
extern uint8_t key0[];
extern parse_bin_cb_t cb_head;

struct IotwBinConfigureQuery msgConfigQuery __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ConfigureQuery,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default,
	.theFormat = IotwBinConfigureFormat_Bin,
	.theRequestedVersion = IotwBinConfigureRequestedVersion_Default
};

struct IotwBinConfigureReply msgConfigReply __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ConfigureReply,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default,
};

struct IotwBinClientJoinQuery msgJoinQuery __attribute__ ((aligned (4))) = {
	.theHeader.theCommand = IotwBinMessage_ClientJoinQuery,
	.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default,
	.theFeatures = IotwBinClientJoinQueryFeatures_OK
};

int32_t hasher_loop(int sock)
{
	int       recv_size =0;
	uint8_t   hash[32];
	head_t    head;

	iotw_parse_init();

	DBG_LOGI(TAG, "--- Send Configuration ---");

	if (iotw_send_bin(sock,
		PARSER_MSG_ENCRYPTED_0_FLAG,
		(void *)&msgConfigQuery,
		sizeof(msgConfigQuery),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "Configuration - send failed");
		mem_queue_free(&queue);
		mem_fifo_free(&fifo);
		return -1;
	}

	/*
	FIXME!!!
	*/
	if (iotw_receive_packet(sock, &head, buff, sizeof(msgConfigReply)+2) < 0) {
		mem_queue_free(&queue);
		mem_fifo_free(&fifo);
		return -1;
	}

	iotw_bin_decrypt1(buff, buff, sizeof(msgConfigReply)+2, key0);
	memcpy(&msgConfigReply, buff, sizeof(msgConfigReply));

	DBG_LOGI(TAG, "ConfigureReply Received (%d)", head.len);

	DBG_LOGI(TAG, "--- Send ClientJoinQuery ---");

	iotw_sha3_256(hash, keys_get_serial(), 8);
	memcpy(&msgJoinQuery.theSerialNumber, keys_get_serial(), 8);

	hasher_print_hash(hash);

	uECC_sign(keys_get_private_key(), hash, sizeof(hash), (uint8_t *) (&msgJoinQuery.theSignature), uECC_secp256k1());

	if (iotw_send_bin(sock,
		PARSER_MSG_ENCRYPTED_0_FLAG,
		(void *)&msgJoinQuery,
		sizeof(msgJoinQuery),
		NULL,
		0,
		NULL) < 0)
	{
		DBG_LOGE(TAG, "ClientJoinQuery - send failed");
		mem_queue_free(&queue);
		mem_fifo_free(&fifo);
		return -1;
	}

	while(1) {
		if(event_get(EVENT_GROUP_SERVICE, SERVICE_EVENT_OTA_STARTED)){
			DBG_LOGW(TAG, "OTA started. Hasher bypassed during OTA...");
			sleep_ms(10000);
		} else {
			recv_size = sock_receive(sock, buff, 512);

			if (recv_size == 0) {
				DBG_LOGI(TAG, "Socket Timout - exiting gracefully (loop)");
				mem_queue_free(&queue);
				mem_fifo_free(&fifo);
				return -1;
			}
			if (recv_size < 0) {
				if (sock_geterror() == 11) continue;
				DBG_LOGE(TAG, "Error receiving head");
				mem_queue_free(&queue);
				mem_fifo_free(&fifo);
				return -1;
			}

			iotw_parse_bin(buff, recv_size, sock);

			while(!mem_queue_is_empty(&queue)){
				bin_msg_t msg;
				mem_queue_remove(&queue, &msg, sizeof(msg));

				iotw_parse_bin_cb_f_t cb = iotw_parse_bin_cb_get_cb(&cb_head, msg.theCommand);
				if(cb){
					cb(&msg, sizeof(msg));
				}else{
					DBG_LOGW(TAG, "No callback for request found. Request dropped.");
				}

			}

#if defined(__XTENSA__)
#if !defined(ESP8266_SDK_VERSION_2)
			esp_task_wdt_reset();
#endif
			taskYIELD();
#endif
		}
#if defined(__XTENSA__)
#if !defined(ESP8266_SDK_VERSION_2)
		esp_task_wdt_reset();
#endif
		taskYIELD();
#endif
	}
}
