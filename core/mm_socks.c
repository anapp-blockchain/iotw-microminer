#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(CONFIG_PLATFORM_8711B)
#include <unistd.h>
#endif

#if __GNUC__ > 3
#if !defined(ESP8266_SDK_VERSION_2)
#include <errno.h>
#endif
#include <stdint.h>
#endif

#if defined (__STM32__)

#include "cmsis_os.h"

#endif // __STM32__

#if defined (__XTENSA__) || defined (__STM32__) || defined(CONFIG_PLATFORM_8711B)

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#endif

#if defined (__XTENSA__) || defined (__STM32__)
#include "lwip/apps/sntp.h"
#endif

#if defined(CONFIG_PLATFORM_8711B)
#include <errno.h>
#endif

#if defined (__mips__)

#include "api/libtcpip/lwip/sockets.h"
#include "api/libtcpip/lwip/sys.h"
#include "api/libtcpip/lwip/netdb.h"
#include "api/libtcpip/lwip/dns.h"
#include "api/libtcpip/lwip/err.h"

#endif

#if defined (__APPLE__) || defined (__linux__)

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/types.h>


#endif

#include "logger.h"
#include "mm_socks.h"

static const char *TAG = "sock";

int8_t sock_init(void)
{

	int sock;
	//Create socket
	sock = socket(AF_INET , SOCK_STREAM , 0);
	if (sock < 0)
	{
		DBG_LOGE(TAG, "Could not create socket. Err: %d %s", sock, strerror(errno));
		return 0;
	}
	DBG_LOGI(TAG, "Socket created");

	return sock;
}

int8_t sock_settimeout(int s, int32_t timeout)
{
	struct timeval tv;

	tv.tv_sec = timeout;  /* 30 Secs Timeout */
	tv.tv_usec = 0;

	if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval)) != 0) {
		DBG_LOGE(TAG, "setsockopt Error: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int8_t sock_keepalive(int s, int8_t enable)
{
	if (enable) {
		int flags =1;
		if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags))) {
			DBG_LOGE(TAG,"setsocketopt(), SO_KEEPALIVE");
			return -1;
		}
#if defined (__APPLE__)
#define TCP_KEEPIDLE TCP_KEEPALIVE
#endif // __APPLE__
		flags = 10;
		if (setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&flags, sizeof(flags))) {
			DBG_LOGE(TAG, "setsocketopt(), SO_KEEPIDLE");
			return -1;
		}
	}
	return 0;
}

int8_t sock_setblocking(int s, int32_t mode)
{
	int32_t opt;
	int32_t ret;

	opt = fcntl(s, F_GETFL, 0);
	if (opt == -1) {
		DBG_LOGE(TAG, "Error getting flags for socket %s", strerror(errno));
		return -1;
	}
	if (mode == 1) {
		opt |= O_NONBLOCK;
	} else {
		opt &= ~O_NONBLOCK;
	}
	ret = fcntl(s, F_SETFL, opt);
	if (ret == -1) {
		DBG_LOGE(TAG, "Error setting flags for socket %s", strerror(errno));
		return -1;
	}
	return 0;
}

int8_t sock_connect(int s, const char *address, const char *port)
{
	struct addrinfo hints, *res;
	struct in_addr *addr;

	DBG_LOGI(TAG, "Connecting to server: %s:%s", address, port);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */

	int err = getaddrinfo(address, port, &hints, &res);
	DBG_LOGI(TAG, "GetAddrInfo");

	if(err != 0 || res == NULL) {
		DBG_LOGE(TAG, "DNS lookup failed Err: %d %s", err, strerror(err));
		return -1;
	}

	/* Code to print the resolved IP.
	Note: inet_ntoa is non-reentrant, look at ipaddr_ntoa_r for "real" code */
	addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
	DBG_LOGI(TAG, "DNS lookup succeeded. IP=%s", inet_ntoa(*addr));

	if(connect(s, res->ai_addr, res->ai_addrlen) != 0) {
		DBG_LOGE(TAG, "Connection Error: %s", strerror(errno));
		close(s);
		freeaddrinfo(res);
		return -1;
	}

	freeaddrinfo(res);
	DBG_LOGI(TAG, "Connected");
	return 0;
}

int32_t sock_receive(int sock, void *buf, int size)
{
	int recv_size;
	recv_size = recv(sock, buf, size, 0);

	if( recv_size == 0) {
		DBG_LOGE(TAG, "Received bytes: %d Error: $%d %s", recv_size, errno, strerror(errno));
	}

	if (recv_size < 0) {
		DBG_LOGE(TAG, "Connection Lost %d %s", errno, strerror(errno));
	}

	return recv_size;
}

int32_t sock_receive_all(int sock, void *buf, int size)
{
	int recv_size;
	int size_to_recv;

	recv_size = 0;
	size_to_recv = 0;
	while(size_to_recv < size) {
		recv_size = sock_receive(sock, (((uint8_t *)buf) + size_to_recv), (size - size_to_recv));
		if (recv_size <= 0) {
			return -1;
		}
		size_to_recv += recv_size;
	}
	return size;
}

void sock_close(int sock)
{
	close(sock);
}

int32_t sock_send_data(int s, void *data, uint16_t size)
{
	int32_t sent = send(s , data , size , 0);
	if( sent < 0)
	{
		DBG_LOGE(TAG, "Sending failed");
		return -1;
	}
	return 0;
}

void sock_ntp_init(void)
{
	DBG_LOGI(TAG, "Initializing SNTP");
#if defined (__XTENSA__) || defined (__STM32__)
	if(sntp_enabled()){
		sntp_stop();
	}
	sntp_setoperatingmode(SNTP_OPMODE_POLL);
	sntp_setservername(0, "time.google.com");
	sntp_init();
#elif defined (__APPLE__) || defined (__linux__) || defined (__mips__) || defined(CONFIG_PLATFORM_8711B)
#else
	DBG_LOGE(TAG, "FIXME: Do we need SNTP on this architecture")
#error Undefined Architecture
#endif 
}

int sock_geterror(void)
{
	return errno;
}
