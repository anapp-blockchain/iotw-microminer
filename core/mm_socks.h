#ifndef _SOCKS_H
#define _SOCKS_H

#if defined(CONFIG_PLATFORM_8711B)
#include <basic_types.h>
#endif

int8_t  sock_init(void);
int8_t sock_connect(int sock, const char *address, const char *port);
int32_t sock_receive(int sock, void *buf, int size);
void    sock_close(int sock);
int32_t sock_send_data(int s, void *data, uint16_t size);
int32_t sock_receive_all(int sock, void *buf, int size);
void sock_ntp_init(void);
int8_t sock_settimeout(int s, int32_t timeout);
int8_t sock_setblocking(int s, int32_t mode);
int sock_geterror(void);
int8_t sock_keepalive(int s, int8_t enable);

#endif // _SOCKS_H
