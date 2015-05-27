[![Build Status](https://travis-ci.org/Ongy/pam_totp.svg?branch=master)](https://travis-ci.org/Ongy/pam_totp)
# pam_totp
A pam authentication module that does totp based authentication

# totp

This module does time based one time passwords according the rfc6238
I chose to do them with a sha512 hash for now. I intend to add a way to specify other hashes later

# This is WIP so some parts are still missing
== What works ==
 * sha512
 * reading a base32 encoded password from a file
 * using either user or system files

== What doesn't work ==
 * Any other hash (code for sha1 exists but cannot be used yet)
 * Any kind of configuration
 * saving used time slices
