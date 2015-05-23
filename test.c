void run_htop_tests();

int main(int argc, char ** argv)
{
	(void) argc;
	(void) argv;
#ifdef POLARSSL_SELF_TEST
	sha512_self_test(1);
#endif
	run_hotp_tests();
	return 0;
}
