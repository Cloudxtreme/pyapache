#!/usr/bin/python
"""
Apache Portable Runtime (APR) MD5 Calculation
by Mike Crute on July 12, 2008
for SoftGroup Interactive, Inc.
Released under the terms of the BSD license.

This is basically a feature-complete implementation of the MD5
algorithm used by the APR, Apache and the htpasswd tool. APR
takes a different approach to generating MD5 sums which is a
little bit wierd.

This is a pythonic adaption of the C code in the APR library.
If there are any questions please refer directly to the C code.
You'll find it in apache subversion under
/ap/apr-util/crypto/apr_md5.c
"""

import string
from hashlib import md5
from random import random
from math import floor

__all__ = ["generate_md5", "generate_salt", "generate_short_salt"]

# Defined as such for brevity
md5digest = lambda x: md5(x).digest()


def ap_to64(input, count=4):
    """Weird-ass implementation of base64 conversion used by the
    APR library.
    """
    chars = "./0123456789%s%s" % (string.uppercase, string.lowercase)
    output = ""
    input = int(input) # Need ints to do binary math

    for i in range(0, count):
        output += chars[input & 0x3f] # Take 6 bits right
        input >>= 6 # shift by 6 bits

    return output


def generate_short_salt():
    """Generate a short, 2-character salt.
    This is suitable for use in the htpasswd crypt routine.
    """
    return generate_salt()[0:2]


def generate_salt():
    """Mine a little salt for your passwords.
    Returns 8 random characters in base64. It is 4 + 4 because the original
    implmentation was in C and they wanted it it fit nicely in an integer.
    """
    salt = ap_to64(floor(random() * 16777215))
    salt += ap_to64(floor(random() * 16777215))
    return salt


def generate_md5(passwd, salt=None):
    """Generate an APRfied MD5 hash.
    This was adapted directly from the C code in the APR library.
    It was made more pythonic where possible but please reference
    the APR code for a better understanding of what's going on.
    """
    # I know not what this means or how it may change in the future
    # (well OK, its the APR version that generated the hash) and
    # I don't think it is really "checked" by Apache but I'm too
    # lazy to confirm this.
    MAGIC_TOKEN = "$apr1$"

    # Mainly just used for testing but why not leave it?
    salt = salt if salt else generate_salt()

    # Start with our password in the clear, a little magic and
    # a pinch of salt
    message = "%s%s%s" % (passwd, MAGIC_TOKEN, salt)

    # Then just as many characters of the MD5(pw, salt, pw)
    retval = md5digest(passwd + salt + passwd)
    passlen = len(passwd)
    while passlen > 0:
        end = 16 if passlen > 16 else passlen
        message += retval[0:end]
        passlen -= 16

    # Then something really wierd
    passlen = len(passwd)
    while passlen != 0:
        if passlen & 1:
            message += chr(0)
        else:
            message += passwd[0]
        passlen >>= 1

    retval = md5digest(message)

    for i in range(0, 1000):
        if i & 1:
            message = passwd
        else:
            message = retval[0:16]

        if i % 3:
            message += salt

        if i % 7:
            message += passwd

        if i & 1:
            message += retval[0:16]
        else:
            message += passwd

        retval = md5digest(message)

    # Now make the output string
    output = ap_to64((ord(retval[0]) << 16) | (ord(retval[6]) << 8) | ord(retval[12]))
    output += ap_to64((ord(retval[1]) << 16) | (ord(retval[7]) << 8) | ord(retval[13]))
    output += ap_to64((ord(retval[2]) << 16) | (ord(retval[8]) << 8) | ord(retval[14]))
    output += ap_to64((ord(retval[3]) << 16) | (ord(retval[9]) << 8) | ord(retval[15]))
    output += ap_to64((ord(retval[4]) << 16) | (ord(retval[10]) << 8) | ord(retval[5]))
    output += ap_to64(ord(retval[11]), 2)

    return "%s%s$%s" % (MAGIC_TOKEN, salt, output)


def test_driver():
    """Run this to verify that the library is functioning properly.
    This one test case should be enough to verify the functionality.
    """
    output = generate_md5("test", "yTbof...")
    assert output == "$apr1$yTbof...$r3r2AZWwYNbWRfNmLfrEh1"
    print "Passed the test!"

if __name__ == "__main__":
    test_driver()
