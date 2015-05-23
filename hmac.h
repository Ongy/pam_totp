#ifndef _HMAC_H_
#define _HMAC_H_

#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

/*
 * This function calculates the hmac of the key and message given as arguments
 * This function writes the hmac into dst and does check for buffer overflow
 */
int calculate_hmac_scha512(uint8_t * key, size_t keysize,
			   uint8_t * message, size_t msgsize,
			   uint8_t * dst, size_t maxlen);

#endif /*_HMAC_H_*/
