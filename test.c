#include <stdio.h>

int run_hmac_tests();
int run_hotp_tests();

int main(int argc, char ** argv)
{
	(void) argc;
	(void) argv;
#ifdef POLARSSL_SELF_TEST
	sha512_self_test(1);
#endif
	if(!run_hmac_tests()) {
		fprintf(stderr, "Failed to validate hmac test\n");
		return -1;
	}
	if(!run_hotp_tests()) {
		fprintf(stderr, "Failed to validate htop test\n");
		return -1;
	}
	return 0;
}
