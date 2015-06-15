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
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "totp.h"
#include "util.h"
#include "secret.h"

#define DEFAULT_USER "nobody"

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


PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
	int retval;
	char buffer[17];
	char totp[9];
	const struct pam_conv *conv;
	const char *user;
	unsigned slice;
	uint8_t secret[128];
	size_t seclen;

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

	slice = get_time_slice();

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Token: %s\n", buffer);

	seclen = get_secret(user, secret, sizeof(secret));

	user = NULL;

	retval = is_valid(secret, seclen, slice, totp)
		 ? PAM_AUTH_ERR : PAM_SUCCESS;
	memset(secret, 0, sizeof(secret));
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
