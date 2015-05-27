#ifndef _TOTP_H_
#define _TOTP_H_
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


#include <stdint.h>
int get_totp_sha512(const uint8_t * hashdata, size_t len, uint64_t time,
		    char * dst, size_t maxlen);
int is_valid(const uint8_t *key, size_t keylen, unsigned time,
	     const char * token);
#endif /*_TOTP_H_*/
