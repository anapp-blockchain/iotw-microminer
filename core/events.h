#ifndef _EVEMNTS_H
#define _EVEMNTS_H

#ifdef CONFIG_PLATFORM_ESP8266
#include <esp8266/eagle_soc.h>
#endif

#ifdef ESP8266_SDK_VERSION_2
#include <esp_common.h>
#endif

void event_init(void);
void event_set(uint32_t group, uint32_t event);
void event_clr(uint32_t group, uint32_t event);
int32_t event_get(uint32_t group, uint32_t event);
int32_t event_wait(uint32_t group, uint32_t event);

enum event_group {
	EVENT_GROUP_HASHER = 0,
	EVENT_GROUP_WIFI,
	EVENT_GROUP_SERVICE,
	EVENT_GROUP_COUNT
};

#if defined(__linux__) || defined(__STM32__)
#define BIT0  0x01
#define BIT1  0x02
#define BIT2  0x04
#define BIT3  0x08
#define BIT4  0x10
#define BIT5  0x20
#define BIT6  0x40
#define BIT7  0x80
#endif

#define HASHER_EVENT_CONNECTED    BIT0
#define HASHER_EVENT_HASHING      BIT1
#define HASHER_EVENT_GOTSERIAL    BIT2
#define HASHER_EVENT_MINING       BIT3

#define WIFI_EVENT_CONNECTED      BIT0
#define WIFI_EVENT_GOT_IP         BIT1
#define WIFI_EVENT_SC_DONE        BIT2
#define WIFI_EVENT_SC_STARTED     BIT3
#define WIFI_EVENT_SC_ABORT       BIT4
/* BIT5 is not used */
#define WIFI_EVENT_SC_COMPLETED   BIT6

#define SERVICE_EVENT_CONNECTED   BIT0
#define SERVICE_EVENT_OTA_READY   BIT1
#define SERVICE_EVENT_FORCE_OTA   BIT2
#define SERVICE_EVENT_RESET_WIFI  BIT3
#define SERVICE_EVENT_GEO_STARTED  BIT4
#define SERVICE_EVENT_OTA_STARTED  BIT5

#endif // _EVENTS_H
