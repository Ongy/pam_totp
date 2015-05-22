#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define DEFAULT_USER "nobody"

#define TIME_STEP 30

#ifndef NULL
#define NULL 0
#endif /*NULL*/

#ifndef max
#define max(x,y) (x) > (y) ? (x) : (y)
#endif /*max*/

#define SECRET "secret"

static int get_otp_token(char * buffer, size_t len,
			 const struct pam_conv * conv)
{
	struct pam_message msg, * msgp;
	struct pam_response * resp;
	int retval;

	msg.msg_style = PAM_PROMPT_ECHO_ON;
	msg.msg = "Password:";
	msgp = &msg;

	retval = (*conv->conv)(1, (const struct pam_message **) &msgp,
		      (struct pam_response **) &resp, conv->appdata_ptr);
	if(retval != PAM_SUCCESS)
		return retval;
	if(resp->resp) {
		if(strlen(resp->resp) < len) {
			strcpy(buffer, resp->resp);
			retval = PAM_SUCCESS;
		}
		else {
			retval = PAM_BUF_ERR;
		}
		free(resp->resp);
	}
	else {
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



PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char ** argv)
{
	int retval;
	char buffer[17];
	const struct pam_conv * conv;
	const char * user;

	(void) flags; (void) argc; (void) argv;
	user = NULL;

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Hi\n");

	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
		return retval;

	if(user == NULL || *user == '\0') {
		retval = pam_set_item(pamh, PAM_USER, DEFAULT_USER);
		if(retval != PAM_SUCCESS)
			return PAM_USER_UNKNOWN;
	}

	retval = pam_get_item(pamh, PAM_CONV, (const void **)&conv);

	if(retval != PAM_SUCCESS)
		return retval;

	retval = get_otp_token(buffer, sizeof(buffer), conv);
	if(retval != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_AUTH | LOG_WARNING,
			"Failed to get password\n");
		return retval;
	}

	pam_syslog(pamh, LOG_AUTH | LOG_WARNING, "Token: %s\n", buffer);

	user = NULL;

	retval = strcmp(SECRET, buffer) ? PAM_AUTH_ERR : PAM_SUCCESS;

	return retval = PAM_SUCCESS; /*TODO remove for usefulness*/
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc,
			      const char ** argv)
{
	(void) pamh; (void) flags; (void) argc; (void) argv;
	return PAM_SUCCESS;
}
