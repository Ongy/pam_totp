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
#include "util.h"

#define TIME_STEP 30

int read_base32(const char *src, uint8_t * dst, size_t maxlen)
{
	const char * c;
	unsigned i;

	for(c = src; *c && i < maxlen; ++c, ++i) {
		if(*c >= 'A' && *c <= 'Z')
			*(dst+i) = *c - 'A';
		else if (*c >= '2' && *c <= '7')
			*(dst+i) = *c - '2' + 26;
		else if(*c >= 'a' && *c <= 'z')
			*(dst+i) = *c - 'a';
		else
			return -1;
	}
	if(*c)
		return -1;
	return i;
}

unsigned get_time_slice()
{
	time_t t;
	time(&t);
	return t / TIME_STEP;
}

