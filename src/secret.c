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

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>
#include "secret.h"
#include "util.h"



#define SYSTEM_DIR "/etc/pam_totp/"
#define CONFIG_NAME "/.pam_totp"

FILE *open_file(const char *user)
{
	char buffer[512];
	char pwbuffer[1024];
	struct passwd pw;
	struct passwd *pwp;

	snprintf(buffer, sizeof(buffer), "%s%s", SYSTEM_DIR, user);

	if(access(buffer, F_OK) == 0) {
		return fopen(buffer, "r");
	}
	getpwnam_r(user, &pw, pwbuffer, sizeof(pwbuffer), &pwp);
	if(!pwp)
		return NULL;
	snprintf(buffer, sizeof(buffer), "%s%s", pw.pw_dir, CONFIG_NAME);
	if(access(buffer, F_OK) == 0) {
		return fopen(buffer, "r");
	}
	printf("Could not find a file\n");
	return NULL;
}

ssize_t get_secret(const char *user, uint8_t *dst, size_t maxlen)
{
	FILE *f;
	char buffer[512];
	size_t ret;

	if(!(f = open_file(user)))
		return -1;
	memset(buffer, 0, sizeof(buffer));
	ret = fread(buffer, 1, sizeof(buffer), f);
	if(ret == 0 && !feof(f)) {
		fclose(f);
		fprintf(stderr, "Failed to read secret file: %s\n",
			strerror(errno));
		return -1;
	}
	fclose(f);

	if(buffer[ret - 1] == '\n')
		buffer[ret - 1] = '\0';

	return read_base32(buffer, dst, maxlen);
}
