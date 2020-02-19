#ifndef _IOTW_SUP_H
#define _IOTW_SUP_H

#pragma pack(push, 1)
typedef struct {
	char		id[4];
	uint8_t		flags;
	uint8_t		ver;
	uint32_t	len;
} head_t;
#pragma pack(pop)

int32_t iotw_send_packet(int s, void *pkt, uint32_t size);
int32_t iotw_receive_head(int sock, head_t *h);
int32_t iotw_receive_packet(int sock, head_t *h, void *buf, int32_t buf_size);

#endif // _IOTW_SUP_H
