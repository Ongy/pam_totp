[![Build Status](https://travis-ci.org/Ongy/pam_totp.svg?branch=master)](https://travis-ci.org/Ongy/pam_totp)
# pam_totp
A pam authentication module that does totp based authentication

# totp

This module does time based one time passwords according the rfc6238
I chose to do them with a sha512 hash for now. I intend to add a way to specify other hashes later

# This is WIP and most of it is if even a sketch
Since this is currently a work in progress it doesn't work and I haven't defined a proper configuratin style yet. 
The current plan is to have a system directory '/etc/totp' where system users can be configured and '$HOME/.totp' for normal users.
