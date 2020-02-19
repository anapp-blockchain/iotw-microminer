#if defined (__STM32__) || defined(CONFIG_PLATFORM_8711B)

#include "FreeRTOS.h"
#include "cmsis_os.h"

#endif

#include <stdio.h>

#if !defined(CONFIG_PLATFORM_8711B)
#include <unistd.h>
#endif

#if __GNUC__ > 3
#include <stdint.h>
#include <stdbool.h>
#endif

#include "events.h"
#include "arch_generic.h"

volatile static uint32_t event_groups[EVENT_GROUP_COUNT];

void event_init(void)
{
	int i;

	for (i = 0 ; i < EVENT_GROUP_COUNT ; i++) {
		event_groups[i] = 0;
	}
}

void event_set(uint32_t group, uint32_t event)
{
	event_groups[group] |= event;
}

void event_clr(uint32_t group, uint32_t event)
{
	event_groups[group] &= ~event;
}

int32_t event_get(uint32_t group, uint32_t event)
{
	return event_groups[group] & event;
}

int32_t event_wait(uint32_t group, uint32_t event)
{
  while (1) {
    if (event_get(group, event))
      return event_get(group, event);
    sleep_ms(200);
  };
}
