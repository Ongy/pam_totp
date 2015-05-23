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

static int get_time_slice()
{
	time_t t;
	time(&t);
	return t / TIME_STEP;
}

static int get_hotp(const char *user, char *dst)
{
	uint8_t buffer[64];
	uint8_t secbuf[64];
	uint8_t offset;
	size_t secsize;
	uint64_t counter;
	uint32_t value;
	mpi secret;
	(void) user;
	counter = get_time_slice();
	/*TODO move this to the beginning of the module */
	counter = htobe64(counter);

	mpi_init(&secret);
	if(mpi_read_string(&secret, 32, SECRET) != 0) {
		fprintf(stderr, "What?\n");
		return -1;
	}
	if(mpi_write_binary(&secret, secbuf, sizeof(secbuf)) != 0) {
		return -1;
	}
	secsize = mpi_size(&secret);
	calculate_hmac_scha512(secbuf + (sizeof(secbuf)-secsize), secsize,
			       (uint8_t *) &counter, 8, buffer, 64);
	memset(secret.p, 0, secret.n);
	mpi_free(&secret);

	offset = buffer[63] & 0x0F;
	value = *((uint32_t *) (buffer + offset));
	value = be32toh(value);
	value &= 0x7FFFFFFF;
	value = value % 100000000;

	sprintf(dst, "%08d", value);
	return -1;
}

int main(int argc, char ** argv)
{
	(void) argc;
	(void) argv;
	char buffer[9];
	get_hotp(NULL, buffer);
	printf("%s\n", buffer);
	return 0;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh, int flags,
				   int argc, const char **argv)
{
	int retval;
	char buffer[17];
	char hotp[9];
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

	get_hotp(user, hotp);

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Hotp: %s\n", hotp);

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
