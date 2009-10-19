#!/usr/bin/python
"""
Apache htaccess File Library
by Mike Crute on July 12, 2008
for SoftGroup Interactive, Inc.
Released under the terms of the BSD license.

A collection of classes and functions to manipulate apache htaccess files.
"""

__all__ = ["generate_user"]


def hash_password(passwd, ctype="crypt"):
    """Create an Apache-style password hash.
    This is basically just a simplfified interface to apachelib.password
    for use in generating htaccess files. Valid ctypes are crypt, sha and
    md5.
    """
    if ctype is "crypt":
        from apachelib.password import crypt_password
        return crypt_password(passwd)
    elif ctype is "sha":
        from apachelib.password import sha_password
        return sha_password(passwd)
    elif ctype is "md5":
        from apachelib.password import md5_password
        return md5_password(passwd)

    # We should never get here
    raise ValueError("%s is not a valid value for ctype." % ctype)


def generate_user(username, passwd, ctype="crypt"):
    """Generate a single htaccess line.
    """
    return "%s:%s" % (username, hash_password(passwd, ctype))
