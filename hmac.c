#include "hmac.h"

#include <string.h>
#include <stdlib.h>

#include "sha512.h"

static void apply_padding(uint8_t * data, size_t size, uint8_t pad)
{
	unsigned i, j;
	uint32_t xor32;
	uint32_t *xor32p;
	uint64_t xor64;
	uint64_t *xor64p;

	xor32 = 0;
	xor64 = 0;
	xor32p = (uint32_t *) data;
	xor64p = (uint64_t *) data;

	for (i = 0; i < 4; ++i) {
		xor32 |= pad << i;
	}
	xor64 = xor32 | ((uint64_t) xor32) << 4;

	for (i = 0; i < size / sizeof(void *); ++i) {
		if (sizeof(void *) == 4) {
			xor32p[i] ^= xor32;
		} else if (sizeof(void *) == 8) {
			xor64p[i] ^= xor64;
		} else {
			for (j = 0; j < sizeof(void *); ++j)
				data[i * sizeof(void *) + j] ^= pad;
		}
	}
	i *= sizeof(void *);
	for (; i < size; ++i) {
		data[i] ^= pad;
	}
}

int calculate_hmac_scha512(uint8_t * key, size_t keysize,
			   uint8_t * message, size_t msgsize,
			   uint8_t * dst, size_t maxlen)
{
	uint8_t *hashbuffer;
	uint8_t keybuffer[1024];
	uint8_t outbuffer[64];
	int ret;

	if (maxlen < 64)
		return -1;
	ret = 0;
	hashbuffer = calloc(msgsize > 1024 ? msgsize + 1024 : 2048, 1);
	memset(keybuffer, 0, 1024);

	if (keysize > 1024) {
		sha512(key, keysize, keybuffer, 0);
	} else {
		memcpy(keybuffer, key, keysize);
	}

	memcpy(keybuffer, hashbuffer, 1024);
	apply_padding(hashbuffer, 1024, 0x36);
	memcpy(hashbuffer + 1024, message, msgsize);

	sha512(hashbuffer, 1024 + msgsize, outbuffer, 0);

	memcpy(keybuffer, hashbuffer, 1024);
	apply_padding(hashbuffer, 1024, 0x5c);
	memcpy(hashbuffer + 1024, outbuffer, sizeof(outbuffer));

	sha512(hashbuffer, 1024 + sizeof(outbuffer), dst, 0);

	free(hashbuffer);
	return ret;
}
