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

#define PAM_SM_AUTH

#include <endian.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "hmac.h"
#include "bignum.h"
#include "sha512.h"
#include "totp.h"


#ifndef NULL
#define NULL 0
#endif /*NULL*/
#ifndef max
#define max(x,y) (x) > (y) ? (x) : (y)
#endif				/*max */

static int get_truncate(const uint8_t * hash, size_t len, char * buffer,
			size_t maxlen)
{
	uint32_t value;
	uint8_t offset;
	offset = hash[len-1] & 0x0F;
	value = *((uint32_t *) (hash+offset));
	value = be32toh(value) & 0x7FFFFFFF;
	value %= 100000000;

	return snprintf(buffer, maxlen, "%08d", value);
}


int get_totp_sha512(const uint8_t * hashdata, size_t len, uint64_t time,
		    char * dst, size_t maxlen)
{
	uint8_t buffer[64];
	uint64_t counter = htobe64(time);

	memset(buffer, 0, sizeof(buffer));

	calculate_hmac_sha512(hashdata, len, (uint8_t *) &counter,
				     sizeof(counter), buffer, sizeof(buffer));

	return get_truncate(buffer, sizeof(buffer), dst, maxlen);
}

static int get_totp_sha1(const uint8_t * hashdata, size_t len, uint64_t time,
		    char * dst, size_t maxlen)
{
	uint8_t buffer[20];
	uint64_t counter = htobe64(time);

	memset(buffer, 0, sizeof(buffer));

	calculate_hmac_sha1(hashdata, len, (uint8_t *) &counter,
				   sizeof(counter), buffer, sizeof(buffer));

	return get_truncate(buffer, sizeof(buffer), dst, maxlen);
}

int run_totp_tests()
{
#define SHA1_KEY "12345678901234567890"
#define SHA1_KEYSIZE strlen(SHA1_KEY)
#define SHA512_KEY "1234567890123456789012345678901234567890123456789012345678901234"
#define SHA512_KEYSIZE strlen(SHA512_KEY)
	uint8_t hash[20];
	char buffer[9];
	uint64_t count = 0;
	int ret;

	calculate_hmac_sha1((uint8_t *)SHA1_KEY, SHA1_KEYSIZE,
			    (uint8_t *) &count, sizeof(count), hash, 20);
	get_truncate(hash, sizeof(hash), buffer, sizeof(buffer));
	/* We always get 8char values, rfc has a 6char example, so we do +2*/
	ret = strcmp(buffer+2, "755224");
	if(ret != 0) {
		fprintf(stderr, "hotp null failed\n");
		return 0;
	}
	fprintf(stdout, "Hotp null test ok\n");

	count = be64toh(1);
	calculate_hmac_sha1((uint8_t *)SHA1_KEY, SHA1_KEYSIZE,
			    (uint8_t *) &count, sizeof(count), hash, 20);
	get_truncate(hash, sizeof(hash), buffer, sizeof(buffer));
	/* We always get 8char values, rfc has a 6char example, so we do +2*/
	ret = strcmp(buffer+2, "287082");
	if(ret != 0) {
		fprintf(stderr, "hotp one failed\n");
		return 0;
	}
	fprintf(stdout, "Hotp one test ok\n");

	get_totp_sha1((uint8_t *)SHA1_KEY, SHA1_KEYSIZE, 1, buffer,
								sizeof(buffer));
	ret = strcmp(buffer, "94287082");
	if(ret != 0) {
		fprintf(stderr, "totp sha1 failed\n");
		return 0;
	}
	fprintf(stdout, "Totp sha1 test ok\n");

	get_totp_sha512((uint8_t *)SHA512_KEY, SHA512_KEYSIZE, 1, buffer,
								sizeof(buffer));
	ret = strcmp(buffer, "90693936");
	if(ret != 0) {
		fprintf(stderr, "totp sha512 failed\n");
		return 0;
	}
	fprintf(stdout, "Totp sha512 test ok\n");

	return 1;
}

