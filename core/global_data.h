#ifndef _GLOBAL_DATA_H
#define _GLOBAL_DATA_H

#if __GNUC__ > 3
#include <stdint.h>
#include <stdbool.h>
#endif

#include <dev_state.h>

#define IOTW_DECL_GDATA extern volatile struct gdata * gd;

struct gdata {

	/*
	State structure generic pointer
	*/
	volatile void * state;

	/*
	Soft WDT
	*/
	bool watchdog_enabled;

	/*
	Miner looping
	*/
	bool miner_loop_running;

	/*
	Timer
	*/
	uint32_t time_to_event_sec;

	/*
	Mode
	*/
	uint8_t mode;

	/*
	State changed - will be used by the device to set local flags,
	the mapping/assignments are arbitrary and completely
	device dependent
	*/
	uint8_t state_changed;

	/*
	iotw socket
	*/
	int32_t sock;

	/*
	Got wifi drop
	*/
	bool got_wifi_drop;
};

int32_t gdata_init();

#endif
