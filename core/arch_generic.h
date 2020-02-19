#ifndef _ARCH_H
#define _ARCH_H

#define api_key_google "api_key_google"

void arch_info(void);
void sleep_ms(uint32_t ms);
void arch_nvs_init(void);
int arch_nvs_read(const char *name, void *data, size_t size);
int arch_nvs_write(const char *name, void *data, size_t size);
void arch_rng_init(void);
void arch_restart(void);
uint32_t arch_random(void);
uint32_t arch_geo(int s);
uint32_t arch_get_ms(void);
uint32_t arch_sc_set(uint8_t * ssid, uint8_t * passwd);
uint32_t arch_sc_drop(void);
void wifi_sc_start_task(void);
uint16_t arch_get_model(void);
uint16_t arch_get_maker(void);
uint32_t arch_get_function_set(void);
uint32_t arch_get_firmware(void);

#endif // _ARCH_H
