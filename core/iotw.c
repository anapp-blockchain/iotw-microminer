#include <stdio.h>
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
#endif


#include "mm_socks.h"
#include "iotw.h"
#include "logger.h"
#include "iotwTools.h"

static const char* TAG_IOTW = "iotw";

const uint8_t header[6] = {
	0x49, 0x4f, 0x54, 0x57,
	0x00, 0x01
};

int32_t iotw_send_packet(int s, void *pkt, uint32_t size)
{
	sock_send_data(s, (void *)header, 6);
	sock_send_data(s, (void *)&size, 4);
	sock_send_data(s, pkt, size);
	return 0;
}

int32_t iotw_receive_head(int sock, head_t *h)
{
	int recv_size;

	recv_size = sock_receive_all(sock , h , sizeof(head_t));

	if (recv_size != sizeof(head_t)) {
		DBG_LOGE(TAG_IOTW, "Received incomplete header");
		return -1;
	}
	if (iotw_memcmp(h->id, "IOTW", 4) != 0) {
		DBG_LOGD(TAG_IOTW, "HEAD (%d): %c%c%c%c type: %d", recv_size, h->id[0], h->id[1], h->id[2], h->id[3], h->flags);
		DBG_LOGE(TAG_IOTW, "Received not valid IOTW header");
		return -1;
	}
	DBG_LOGD(TAG_IOTW, "HEAD Received flags: %02x ver: %d len: %d", h->flags, h->ver, h->len);
	return 0;
}

int32_t iotw_receive_packet(int sock, head_t *h, void *buf, int32_t buf_size)
{
	if (iotw_receive_head(sock, h) < 0) {
		return -1;
	}

	if (h->len > buf_size) {
		DBG_LOGW(TAG_IOTW, "Insufficient buffer size for packet %d available %d", h->len, buf_size);
	}
	if (sock_receive_all(sock, buf, buf_size) < 0) {
		DBG_LOGE(TAG_IOTW, "Receiving packet failed");
		return -1;
	}
	return 0;
}
