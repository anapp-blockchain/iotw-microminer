#ifndef _MINER_H
#define _MINER_H

#if __GNUC__ > 3
#include <stdint.h>
#endif 

#if defined(CONFIG_PLATFORM_8711B)
#include <basic_types.h>
#endif

typedef enum {
	MINER_ENV_DUMMY_TEST = 0,
} env_type_t;

void miner_init(void);
int32_t miner_loop(void);
int32_t miner_register(int16_t maker, int16_t model);

void miner_set_mac(uint8_t *mac);
void miner_set_env(env_type_t env);
const char *miner_get_env(void);

#endif // _MINER_H
