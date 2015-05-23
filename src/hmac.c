/**
 *  This file is part of pam_totp (https://github.com/Ongy/pam_totp)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public
 *  License along
 *  with this program; if not, write to the Free Software
 *  Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include "hmac.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sha512.h"
#include "sha1.h"

static const char * NULL_TEST =
	"\xB9\x36\xCE\xE8\x6C\x9F\x87\xAA\x5D\x3C\x6F\x2E\x84\xCB\x5A"
	"\x42\x39\xA5\xFE\x50\x48\x0A\x6E\xC6\x6B\x70\xAB\x5B\x1F\x4A"
	"\xC6\x73\x0C\x6C\x51\x54\x21\xB3\x27\xEC\x1D\x69\x40\x2E\x53"
	"\xDF\xB4\x9A\xD7\x38\x1E\xB0\x67\xB3\x38\xFD\x7B\x0C\xB2\x22"
	"\x47\x22\x5D\x47";

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
		xor32 |= ((uint32_t) pad) << (i * 8);
	}
	xor64 = xor32 | (((uint64_t) xor32) << 32);

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

int calculate_hmac_sha512(const uint8_t * key, size_t keysize,
			  const uint8_t * message, size_t msgsize,
			  uint8_t * dst, size_t maxlen)
{
	uint8_t *hashbuffer;
	uint8_t keybuffer[128];
	uint8_t outbuffer[64];
	int ret;

	if (maxlen < 64)
		return -1;
	ret = 0;
	hashbuffer = calloc(sizeof(keybuffer) + (msgsize > sizeof(outbuffer) ?
			    msgsize : sizeof(outbuffer)), 1);

	memset(keybuffer, 0, sizeof(keybuffer));

	if (keysize > sizeof(keybuffer)) {
		sha512(key, keysize, keybuffer, 0);
	} else {
		memcpy(keybuffer, key, keysize);
	}

	memcpy(hashbuffer, keybuffer, sizeof(keybuffer));
	apply_padding(hashbuffer, sizeof(keybuffer), 0x36);
	memcpy(hashbuffer + sizeof(keybuffer), message, msgsize);

	sha512(hashbuffer, sizeof(keybuffer) + msgsize, outbuffer, 0);

	memcpy(hashbuffer, keybuffer, sizeof(keybuffer));
	apply_padding(hashbuffer, sizeof(keybuffer), 0x5c);
	memcpy(hashbuffer + sizeof(keybuffer), outbuffer, sizeof(outbuffer));


	sha512(hashbuffer, sizeof(keybuffer) + sizeof(outbuffer), dst, 0);

	free(hashbuffer);
	return ret;
}

int calculate_hmac_sha1(const uint8_t * key, size_t keysize,
			const uint8_t * message, size_t msgsize,
			uint8_t * dst, size_t maxlen)
{
	uint8_t *hashbuffer;
	uint8_t keybuffer[64];
	uint8_t outbuffer[20];
	int ret;

	if (maxlen < 64)
		return -1;
	ret = 0;
	hashbuffer = calloc(sizeof(keybuffer) + (msgsize > sizeof(outbuffer) ?
			    msgsize : sizeof(outbuffer)), 1);

	memset(keybuffer, 0, sizeof(keybuffer));

	if (keysize > sizeof(keybuffer)) {
		sha512(key, keysize, keybuffer, 0);
	} else {
		memcpy(keybuffer, key, keysize);
	}

	memcpy(hashbuffer, keybuffer, sizeof(keybuffer));
	apply_padding(hashbuffer, sizeof(keybuffer), 0x36);
	memcpy(hashbuffer + sizeof(keybuffer), message, msgsize);

	sha1(hashbuffer, sizeof(keybuffer) + msgsize, outbuffer);

	memcpy(hashbuffer, keybuffer, sizeof(keybuffer));
	apply_padding(hashbuffer, sizeof(keybuffer), 0x5c);
	memcpy(hashbuffer + sizeof(keybuffer), outbuffer, sizeof(outbuffer));


	sha1(hashbuffer, sizeof(keybuffer) + sizeof(outbuffer), dst);

	free(hashbuffer);
	return ret;
}
int run_hmac_tests()
{
	uint8_t buffer[64];

	calculate_hmac_sha512(NULL, 0, NULL, 0, buffer, sizeof(buffer));

	return memcmp(buffer, NULL_TEST, sizeof(buffer)) == 0;
}
