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

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>
#include "util.h"

#define TIME_STEP 30

int read_base32(const char *src, uint8_t * dst, size_t maxlen)
{
	const char * c;
	char t;
	unsigned i, j;
	uint64_t tmp;
	uint8_t * tp;

	j = 0;
	tmp = 0;
	tp = (uint8_t *) &tmp;
	tp += 3;

	for(i = 0, c = src; *c && i * 5 < maxlen; ++c) {
		if(*c >= 'A' && *c <= 'Z')
			t = *c - 'A';
		else if (*c >= '2' && *c <= '7')
			t = *c - '2' + 26;
		else if(*c >= 'a' && *c <= 'z')
			t = *c - 'a';
		else
			return -1;

		tmp |= ((uint64_t) t) << (40 - (++j * 5));

		if(j == 8) {
			j = 5;
			if(i * 5 + 5 > maxlen)
				return -1;
			tmp = htobe64(tmp);
			memcpy(dst+i*5, tp, 5);
			tmp = 0;
			++i;
			j = 0;
		}
	}
	if(*c)
		return -1;
	if(i * 5 + j > maxlen)
		return -1;
	tmp = htobe64(tmp);
	memcpy(dst + i * 5, tp, j);
	return i * 5 + j;
}

unsigned get_time_slice()
{
	time_t t;
	time(&t);
	return t / TIME_STEP;
}

