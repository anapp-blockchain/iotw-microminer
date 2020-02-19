#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include "uECC.h"
#include "iotwTools.h"
#include "logger.h"
#include "arch_generic.h"

uint8_t privateKey[64];
uint8_t publicKey[129];
uint8_t address[20];

char privateKeyHex[65];
char publicKeyHex[130];
char addressHex[41];

uint8_t deviceSerial[8] = {0, 0, 0, 0, 0, 0, 0, 0};
uint8_t deviceCode[58+1] = {0,};

static const char *privateKeyName = "private_key";

static const char *TAG = "keys";

void keys_init(void)
{
	int privateKeySize = uECC_curve_private_key_size(uECC_secp256k1());
	int publicKeySize = uECC_curve_public_key_size(uECC_secp256k1());

	DBG_LOGI(TAG, "Key Size: %d %d", privateKeySize, publicKeySize);

	arch_nvs_init();

	arch_rng_init();

	iotw_memset(privateKey, 0, privateKeySize);

	if (arch_nvs_read(privateKeyName, privateKey, 32) && privateKey[1] && privateKey[2])
	{
		DBG_LOGI(TAG, "INIT: Private Key Loaded");
		uECC_compute_public_key(privateKey, publicKey, uECC_secp256k1());
	}
	else
	{
		uECC_make_key(publicKey, privateKey, uECC_secp256k1());
		DBG_LOGI(TAG, "INIT: Private Key Generated");
		arch_nvs_write(privateKeyName, privateKey, 32);
	}

	iotw_address_from_public_key(address, publicKey);
	iotw_address_to_hex((uint8_t *)addressHex, address);
	addressHex[40] = 0;
}

uint8_t *keys_get_public_key(void)
{
	return publicKey;
}

uint8_t *keys_get_private_key(void)
{
	return privateKey;
}

char *keys_get_public_key_hex(void)
{
	return publicKeyHex;
}

char *keys_get_private_key_hex(void)
{
	return privateKeyHex;
}

void keys_set_serial(uint8_t *serial)
{
	memcpy(deviceSerial, serial, 8);
}

uint8_t *keys_get_serial(void)
{
	return deviceSerial;
}

void keys_set_device_code(uint8_t * devCode){
	memcpy(deviceCode, devCode, 58);
}

uint8_t *keys_get_device_code(void){
	return deviceCode;
}
