#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__XTENSA__)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#endif

#include "miner.h"
#include "logger.h"
#include "hasher.h"
#include "keys.h"
#include "mm_socks.h"
#include "iotw.h"
#include "events.h"
#include "arch_generic.h"
#include "ver.h"
#include "iotw_parser_bin.h"

#include "iotwTools.h"
#include "IotwBinMessage.h"
#include "IotwBinSerialServerMessage.h"
#include "uECC.h"
#include "global_data.h"

static const char *TAG = "miner";

static int gSock = 0;

IOTW_DECL_GDATA;

typedef struct {
	const char *name;
	const char *port;
} server_t;

typedef struct {
	const char *name;
	const server_t ledger;
	const server_t serial;
} server_set_t;

server_set_t server[] = {
	{ "IOTWNetwork",  { "testnetwork.iotw.fun", "1111" },   { "srv.testnetwork.iotw.fun", "2222" } },
};

const char *miner_env_names[] = {
	"TestNetwork"
};

static env_type_t miner_env = MINER_ENV_DUMMY_TEST;

static const char *miner_env_name = "mm_env";

static uint8_t miner_mac[6];

const char *miner_get_env(void)
{
	return miner_env_names[miner_env];
}

void miner_set_env(env_type_t env)
{
	miner_env = env;
	arch_nvs_write(miner_env_name, &miner_env, sizeof(miner_env));
	DBG_LOGI(TAG, "Miner ENV changed to %s", server[miner_env].name);
}

void miner_set_mac(uint8_t *mac)
{
	memcpy(miner_mac, mac, 6);
}

int32_t miner_get_serial(const char *addr, const char *port, uint8_t *mac, uint16_t model, uint32_t version)
{
	struct IotwBinSerialQuery msgSerialQuery = {
		.theHeader.theCommand = IotwBinMessage_SerialQuery,
		.theHeader.theVersion = IotwBinIotwBinMessageHeaderVersion_Default
	};

#ifdef __IAR_SYSTEMS_ICC__
	__packed
#endif
	struct msgSerialReply_crc {
		struct IotwBinSerialReply reply;
		uint16_t crc;
	}
#ifdef __GNUC__
	__attribute__((packed));
#else
	;
#endif

	struct msgSerialReply_crc mcrca;

	DBG_LOGI(TAG, "--- Request Serial ---");
	int s = sock_init();

	if (s < 0) {
		DBG_LOGE(TAG, "Failed to create socket");
		return -1;
	}

	head_t  head;

	if (sock_connect(s, addr, port) < 0) {
		DBG_LOGE(TAG, "Failed to establish connection to serial server");
		return -1;
	}

	memcpy(&msgSerialQuery.theMac, mac, 6);
	msgSerialQuery.theModel = model;
	msgSerialQuery.theRelease = version;
	memcpy(&msgSerialQuery.thePublicKey, keys_get_public_key(), 64);

	if (iotw_send_bin(s,
		PARSER_MSG_ENCRYPTED_NONE_FLAG,
		(void *)&msgSerialQuery,
		sizeof(msgSerialQuery),
		NULL,
		0,
		NULL) < 0)
	{
			DBG_LOGE(TAG, "miner_get_serial - send failed");
			return -1;
	}

	if (iotw_receive_packet(s, &head, &mcrca, sizeof(mcrca)) < 0) {
		DBG_LOGE(TAG, "miner_get_serial - receive response failed -----");
		return -1;
	}
	sock_close(s);

	keys_set_serial((uint8_t *)&mcrca.reply.theSerialNumber);

	arch_nvs_write("serial_num", (uint8_t *)&mcrca.reply.theSerialNumber, 8);

	event_set(EVENT_GROUP_HASHER, HASHER_EVENT_GOTSERIAL);
	return 0;
}

int32_t miner_register(int16_t maker, int16_t model)
{
	uint8_t serial[8] = {0,};
	uint8_t dev_code[58+1] = {0,};

	if(!arch_nvs_read("serial_num", serial, 8))
	{
		if (miner_get_serial(server[miner_env].serial.name, server[miner_env].serial.port, miner_mac, model, IOTW_VERSION_FW) < 0)
		{
			DBG_LOGE(TAG, "Cannot get hasher serial number. Restarting.");
			return -1;
		}
	} else {
		DBG_LOGI(TAG, "Serial loaded from NVS");
		keys_set_serial(serial);
	}

	iotw_device_code(dev_code, keys_get_public_key(), keys_get_serial());
	keys_set_device_code(dev_code);
	DBG_LOGI(TAG, "Device code: %s", keys_get_device_code());
	event_set(EVENT_GROUP_HASHER, HASHER_EVENT_GOTSERIAL);
	return 0;
}

int32_t miner_loop(void)
{
	gSock = sock_init();
	if (gSock < 0) {
		DBG_LOGE(TAG, "Cannot create socket");
		return -1;
	}

	gd->sock = gSock;

	if (sock_connect(gSock, server[miner_env].ledger.name, server[miner_env].ledger.port) == 0) {
		hasher_loop(gSock);
		event_clr(EVENT_GROUP_HASHER, 0xff);
		DBG_LOGE(TAG, "Connection to ledger lost");
	} else {
		DBG_LOGE(TAG, "Cannot connect to ledger");
	}
	sock_close(gSock);
	gSock = 0;
	return -1;
}

void miner_init(void)
{
	if (arch_nvs_read(miner_env_name, &miner_env, sizeof(miner_env))) {
		DBG_LOGI(TAG, "Miner ENV set to: %s", server[miner_env].name);
	} else {
		miner_set_env(MINER_ENV_DUMMY_TEST);
	}

	iotw_parse_bin_cb_init(&cb_head);

	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_NotificationQuery, hasher_notification, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_ControlQuery, hasher_control_query, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_PingQuery, hasher_ping, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_Unknown, hasher_unknown, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_LedgerVerifyExtQuery, hasher_ledger_verify_ext, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_LedgerVerifyQuery, hasher_ledger_verify, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_BlockVerifyQuery, hasher_block_verify, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_ClientJoinReply, hasher_bin_msg_reply, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_ControlReply, hasher_bin_msg_reply, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_DataReply, hasher_bin_msg_reply, 0);
	iotw_parse_bin_cb_register(&cb_head, IotwBinMessage_MetaDataQuery, hasher_meta_data_query, 0);
}

int miner_get_sock(void)
{
	return gSock;
}
