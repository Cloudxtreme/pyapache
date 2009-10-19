#!/usr/bin/env python
"""
Utilities to manage a hash db of users for apache
"""
import anydbm
import htpasswd
__all__ = ["add_user", "delete_user", "update_user",
           "get_user", "list_users", "raw_add"]


def get_user(user, db):
    """ Get user info from the DB """
    db_dict = anydbm.open(db, 'r')
    ret_user = "%s:%s" %(user, db_dict[user])
    db_dict.close()
    return ret_user


def list_users(db):
    """ List all the users in the DB """
    db_dict = anydbm.open(db, 'r')
    ret_str = '\n'.join(["%s:%s" %(k, v) for k, v in db_dict.iteritems()])
    db_dict.close()
    return ret_str


def add_user(user, passwd, db):
    """ Add user to the DB, creating if need be """
    db_dict = anydbm.open(db, 'c')
    db_dict[user] = htpasswd.hash_password(passwd)
    db_dict.close()
    return True


def raw_add(line, db):
    """ Add raw line to the DB """
    db_dict = anydbm.open(db, 'w')
    user, passwd = line.split(':')
    db_dict[user] = passwd
    db_dict.close()
    return True


def delete_user(user, db):
    """ Remove user from the DB """
    db_dict = anydbm.open(db, 'w')
    del db_dict[user]
    db_dict.close()
    return True


def update_user(user, passwd, db):
    """ Change the users pass in the DB """
    db_dict = anydbm.open(db, 'w')
    if user in db_dict:
        db_dict[user] = htpasswd.hash_password(passwd)
        db_dict.close()
        return True
    else:
        return False
