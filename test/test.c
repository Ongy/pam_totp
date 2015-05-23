#include <stdio.h>

int run_hmac_tests();
int run_totp_tests();

int main(int argc, char ** argv)
{
	(void) argc;
	(void) argv;
	fprintf(stdout, "Starting testsuite for pam_totp\n");
#ifdef POLARSSL_SELF_TEST
	sha512_self_test(1);
#endif

	if(!run_hmac_tests()) {
		fprintf(stderr, "Failed to validate hmac test\n");
		return -1;
	} else {
		fprintf(stdout, "Hmac test ok\n");
	}
	if(!run_totp_tests()) {
		fprintf(stderr, "Failed to validate totp test\n");
		return -1;
	} else {
		fprintf(stdout, "Totp test ok\n");
	}
	return 0;
}
