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

#include <stdio.h>
#include "util.h"
#include "totp.h"

int run_hmac_tests();
int run_totp_tests();
int run_util_tests();

int main(int argc, char ** argv)
{
	(void) argc;
	(void) argv;
	uint8_t buf[20];
	int seclen;
	char tok[9];

	fprintf(stdout, "Starting testsuite for pam_totp\n");
#ifdef POLARSSL_SELF_TEST
	sha512_self_test(1);
#endif

	if(!run_hmac_tests()) {
		fprintf(stderr, "Failed to validate hmac test\n");
		return -1;
	}
	fprintf(stdout, "Hmac test ok\n");

	if(!run_totp_tests()) {
		fprintf(stderr, "Failed to validate totp test\n");
		return -1;
	}
	fprintf(stdout, "Totp test ok\n");

	if(!run_util_tests()) {
		fprintf(stderr, "Failed to run utility tests\n");
		return -1;
	}
	fprintf(stdout, "Utility ok\n");

	/*at the end output the current totp*/
	seclen = read_base32("77777777", buf, sizeof(buf));
	get_totp_sha512(buf, seclen, get_time_slice(), tok, sizeof(tok));
	printf("%s\n", tok);
	return 0;
}
