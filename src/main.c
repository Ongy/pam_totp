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

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
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

#define DEFAULT_USER "nobody"
#define WINDOW 1

#define TIME_STEP 30

#ifndef NULL
#define NULL 0
#endif /*NULL*/
#ifndef max
#define max(x,y) (x) > (y) ? (x) : (y)
#endif				/*max */
#define SECRET "77777777"
static int get_otp_token(char *buffer, size_t len,
			 const struct pam_conv *conv)
{
	struct pam_message msg, *msgp;
	struct pam_response *resp;
	int retval;

	msg.msg_style = PAM_PROMPT_ECHO_ON;
	msg.msg = "Password:";
	msgp = &msg;

	retval = (*conv->conv) (1, (const struct pam_message **) &msgp,
				(struct pam_response **) &resp,
				conv->appdata_ptr);
	if (retval != PAM_SUCCESS)
		return retval;
	if (resp->resp) {
		if (strlen(resp->resp) < len) {
			strcpy(buffer, resp->resp);
			retval = PAM_SUCCESS;
		} else {
			retval = PAM_BUF_ERR;
		}
		free(resp->resp);
	} else {
		retval = PAM_CONV_ERR;
	}
	free(resp);
	return retval;
}

static int get_time_slice()
{
	time_t t;
	time(&t);
	return t / TIME_STEP;
}

static size_t get_hashdata(const char * user, uint8_t * buffer, size_t maxlen)
{
	mpi secret;
	size_t secsize;

	(void) user;
	mpi_init(&secret);
	if(mpi_read_string(&secret, 32, SECRET) != 0) {
		fprintf(stderr, "What?\n");
		return -1;
	}
	if(mpi_size(&secret) <= maxlen) {
		if(mpi_write_binary(&secret, buffer, maxlen) != 0) {
			mpi_free(&secret);
			return -1;
		}
	}
	secsize = mpi_size(&secret);
	mpi_free(&secret);

	return secsize;
}

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


static int get_totp_hmac_sha512(const uint8_t *secret, size_t len,
				uint64_t time, uint8_t *dst, size_t maxlen)
{
	uint64_t counter;

	/*TODO move this to the beginning of the module */
	counter = htobe64(time);

	return calculate_hmac_sha512(secret, len, (uint8_t *) &counter,
				     sizeof(counter), dst, maxlen);
}

static int get_totp_sha512(const uint8_t * hashdata, size_t len, uint64_t time,
		    char * dst, size_t maxlen)
{
	uint8_t buffer[64];

	memset(buffer, 0, sizeof(buffer));

	get_totp_hmac_sha512(hashdata, len, time, buffer, sizeof(buffer));

	return get_truncate(buffer, sizeof(buffer), dst, maxlen);
}

static int get_totp_hmac_sha1(const uint8_t *secret, size_t len,
			      uint64_t time, uint8_t *dst, size_t maxlen)
{
	uint64_t counter;

	/*TODO move this to the beginning of the module */
	counter = htobe64(time);

	return calculate_hmac_sha1(secret, len, (uint8_t *) &counter,
				     sizeof(counter), dst, maxlen);
}

static int get_totp_sha1(const uint8_t * hashdata, size_t len, uint64_t time,
		    char * dst, size_t maxlen)
{
	uint8_t buffer[20];

	memset(buffer, 0, sizeof(buffer));

	get_totp_hmac_sha1(hashdata, len, time, buffer, sizeof(buffer));

	return get_truncate(buffer, sizeof(buffer), dst, maxlen);
}

int run_totp_tests()
{
	uint8_t hash[20];
	char buffer[9];
	uint64_t count = 0;
	int ret;

	calculate_hmac_sha1((uint8_t *)"12345678901234567890", 20,
			    (uint8_t *) &count, sizeof(count), hash, 20);
	get_truncate(hash, sizeof(hash), buffer, sizeof(buffer));
	ret = strcmp(buffer+2, "755224");
	if(ret != 0) {
		fprintf(stderr, "hotp failed\n");
		return 0;
	}
	fprintf(stdout, "Hopt test ok\n");

	get_totp_sha1((uint8_t *)"12345678901234567890", 20, 1, buffer,
								sizeof(buffer));
	ret = strcmp(buffer, "94287082");
	if(ret != 0) {
		fprintf(stderr, "totp sha1 failed\n");
		return 0;
	}
	fprintf(stdout, "Topt sha1 test ok\n");

	get_totp_sha512((uint8_t *)"12345678901234567890", 20, 1, buffer,
								sizeof(buffer));
	ret = strcmp(buffer, "90693936");
	if(ret != 0) {
		fprintf(stderr, "totp sha512 failed\n");
		return 0;
	}
	fprintf(stdout, "Topt sha512 test ok\n");
	return 1;
}

int is_valid_token(const char * user, const char *token)
{
	uint8_t buffer[128];
	char tok[9];
	size_t len;
	int i;
	int slice;

	slice = get_time_slice();

	len = get_hashdata(user, buffer, sizeof(buffer));

	for(i = -WINDOW; i < 0; ++i) {
		get_totp_sha512(buffer, len, slice + i, tok, sizeof(tok));
		if(!strcmp(token, tok))
			return 1;
	}
	return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
	int retval;
	char buffer[17];
	char totp[9];
	const struct pam_conv *conv;
	const char *user;

	(void) flags;
	(void) argc;
	(void) argv;
	user = NULL;

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Hi\n");

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
		return retval;

	if (user == NULL || *user == '\0') {
		retval = pam_set_item(pamh, PAM_USER, DEFAULT_USER);
		if (retval != PAM_SUCCESS)
			return PAM_USER_UNKNOWN;
	}

	retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv);

	if (retval != PAM_SUCCESS)
		return retval;

	retval = get_otp_token(buffer, sizeof(buffer), conv);
	if (retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_AUTH | LOG_WARNING,
			   "Failed to get password\n");
		return retval;
	}

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Token: %s\n", buffer);

	if(!is_valid_token(user, buffer))
		retval = PAM_AUTH_ERR;

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Hotp: %s\n", totp);

	user = NULL;

	retval = strcmp(SECRET, buffer) ? PAM_AUTH_ERR : PAM_SUCCESS;

	return retval = PAM_SUCCESS;	/*TODO remove for usefulness */
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
			      const char **argv)
{
	(void) pamh;
	(void) flags;
	(void) argc;
	(void) argv;
	return PAM_SUCCESS;
}
