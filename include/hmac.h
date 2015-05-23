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

#ifndef _HMAC_H_
#define _HMAC_H_

#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

/*
 * This function calculates the hmac of the key and message given as arguments
 * This function writes the hmac into dst and does check for buffer overflow
 */
int calculate_hmac_sha512(const uint8_t * key, size_t keysize,
			  const uint8_t * message, size_t msgsize,
			  uint8_t * dst, size_t maxlen);

int calculate_hmac_sha1(const uint8_t * key, size_t keysize,
			const uint8_t * message, size_t msgsize,
			uint8_t * dst, size_t maxlen);

#endif /*_HMAC_H_*/
