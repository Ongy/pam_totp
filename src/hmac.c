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
#include <assert.h>

#include "sha512.h"
#include "sha1.h"

#define max(a, b) ((a) < (b) ? (b) : (a))

#define CAL_NAME(x) calculate_hmac_ ## x

#define DEFINE_HASHFUNCTION(name, blocksize, outsize) \
int CAL_NAME(name)(const uint8_t *key, size_t keysize, \
			  const uint8_t *message, size_t msgsize, \
			  uint8_t *dst, size_t maxlen) \
{ \
	uint8_t *hashbuffer; \
	uint8_t keybuffer[(blocksize)]; \
	uint8_t outbuffer[(outsize)]; \
	int ret; \
	\
	assert(maxlen >= (outsize)); \
	if (key == 0 || message == 0) \
		return -1; \
	ret = 0; \
	hashbuffer = calloc(blocksize + max(msgsize, outsize), 1); \
	memset(keybuffer, 0, (blocksize)); \
	\
	if (keysize > (blocksize)) \
		name(key, keysize, keybuffer); \
	else \
		memcpy(keybuffer, key, keysize); \
	\
	memcpy(hashbuffer, keybuffer, (blocksize)); \
	apply_padding(hashbuffer, (blocksize), 0x36); \
	memcpy(hashbuffer + (blocksize), message, msgsize); \
	\
	name(hashbuffer, (blocksize) + msgsize, outbuffer); \
	\
	memcpy(hashbuffer, keybuffer, (blocksize)); \
	apply_padding(hashbuffer, (blocksize), 0x5c); \
	memcpy(hashbuffer + (blocksize), outbuffer, (outsize)); \
	\
	name(hashbuffer, (blocksize) + (outsize), dst); \
	\
	free(hashbuffer); \
	return ret; \
}

static void apply_padding(uint8_t * data, size_t size, uint8_t pad)
{
	unsigned i, j;
	uint32_t xor32;
	uint32_t *xor32p;
	uint64_t xor64;
	uint64_t *xor64p;

	xor32 = 0;
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


DEFINE_HASHFUNCTION(sha512, 128, 64)

DEFINE_HASHFUNCTION(sha1, 64, 20)



static const char * NULL_TEST_SHA512 =
	"\xB9\x36\xCE\xE8\x6C\x9F\x87\xAA\x5D\x3C\x6F\x2E\x84\xCB\x5A"
	"\x42\x39\xA5\xFE\x50\x48\x0A\x6E\xC6\x6B\x70\xAB\x5B\x1F\x4A"
	"\xC6\x73\x0C\x6C\x51\x54\x21\xB3\x27\xEC\x1D\x69\x40\x2E\x53"
	"\xDF\xB4\x9A\xD7\x38\x1E\xB0\x67\xB3\x38\xFD\x7B\x0C\xB2\x22"
	"\x47\x22\x5D\x47";

static const char * KEY_TEST_SHA512 =
	"\x84\xFA\x5A\xA0\x27\x9B\xBC\x47\x32\x67\xD0\x5A\x53\xEA\x03"
	"\x31\x0A\x98\x7C\xEC\xC4\xC1\x53\x5F\xF2\x9B\x6D\x76\xB8\xF1"
	"\x44\x4A\x72\x8D\xF3\xAA\xDB\x89\xD4\xA9\xA6\x70\x9E\x19\x98"
	"\xF3\x73\x56\x6E\x8F\x82\x4A\x8C\xA9\x3B\x18\x21\xF0\xB6\x9B"
	"\xC2\xA2\xF6\x5E";

static const char * FULL_TEST_SHA512 =
	"\x86\x95\x1D\xC7\x65\xBE\xF9\x5F\x94\x74\x66\x9C\xD1\x8D\xF7"
	"\x70\x5D\x99\xAE\x47\xEA\x3E\x76\xA2\xCA\x4C\x22\xF7\x16\x56"
	"\xF4\x2E\xA6\x6E\x3A\xCD\xC8\x98\xC9\x3F\x47\x50\x09\xFA\x59"
	"\x9D\x0B\xB8\x3B\xD5\x36\x5F\x36\xA9\xCB\x92\xC5\x70\x70\x8F"
	"\x8D\xE5\xFA\xE8";

static const char * NULL_TEST_SHA1 =
	"\xFB\xDB\x1D\x1B\x18\xAA\x6C\x08\x32\x4B\x7D\x64\xB7\x1F\xB7"
	"\x63\x70\x69\x0E\x1D";


int run_hmac_tests()
{
	uint8_t buffer[64];
	int ret;

	calculate_hmac_sha1((uint8_t *)"", 0, (uint8_t *)"", 0,
			    buffer, sizeof(buffer));
	ret = memcmp(buffer, NULL_TEST_SHA1, 20);
	if(ret != 0) {
		fprintf(stderr, "hmac1 failed\n");
		return 0;
	}
	fprintf(stdout, "hmac1 test ok\n");

	calculate_hmac_sha512((uint8_t *)"", 0, (uint8_t *)"", 0,
			      buffer, sizeof(buffer));
	ret = memcmp(buffer, NULL_TEST_SHA512, sizeof(buffer));
	if(ret != 0) {
		fprintf(stderr, "hmac512 null failed\n");
		return 0;
	}
	fprintf(stdout, "hmac512 null test ok\n");

	calculate_hmac_sha512((uint8_t *)"key", 3, (uint8_t *) "", 0,
			      buffer, sizeof(buffer));
	ret = memcmp(buffer, KEY_TEST_SHA512, sizeof(buffer));
	if(ret != 0) {
		fprintf(stderr, "hmac512 key failed\n");
		return 0;
	}
	fprintf(stdout, "hmac512 key test ok\n");

	calculate_hmac_sha512((uint8_t *)"key", 3, (uint8_t *)"value", 5,
			      buffer, sizeof(buffer));
	ret = memcmp(buffer, FULL_TEST_SHA512, sizeof(buffer));
	if(ret != 0) {
		fprintf(stderr, "hmac512 full failed\n");
		return 0;
	}
	fprintf(stdout, "hmac512 full test ok\n");

	return 1;
}
