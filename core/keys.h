#ifndef _KEYS_H
#define _KEYS_H

void keys_init(void);
uint8_t *keys_get_public_key(void);
uint8_t *keys_get_private_key(void);
char *keys_get_public_key_hex(void);
char *keys_get_private_key_hex(void);
void keys_set_serial(uint8_t *serial);
uint8_t *keys_get_serial(void);
void keys_set_device_code(uint8_t * devCode);
uint8_t *keys_get_device_code(void);

#endif // _KEYS_H
