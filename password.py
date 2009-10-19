#!/usr/bin/python
"""
Apache Password Hash Generation Functions
by Mike Crute on July 12, 2008
for SoftGroup Interactive, Inc.
Released under the terms of the BSD license.

A collection of functions used to generate Apache-style password hashes.
Algorithm information was collected for various sources around the web
and from analysis of the APR C code.
"""


def crypt_password(passwd):
    """Generate Apache-style CRYPT password hash.
    """
    from crypt import crypt
    from apachelib.md5 import generate_short_salt
    return crypt(passwd, generate_short_salt())


def sha_password(passwd):
    """Generate Apache-style SHA1 password hash.
    """
    from hashlib import sha1
    from base64 import b64encode
    return "{SHA}%s" % b64encode(sha1(passwd).digest())


def md5_password(passwd):
    """Generate Apache-style MD5 password hash.
    """
    from apachelib.md5 import generate_md5
    return generate_md5(passwd)
