"""
PWCache basically manages a database of frequent mistyped typos by a user.
It has two databases, one for temporaraly store the mistyped passwords, under
users public key. The database is only readable and writable by root, and
should be treated as carefully as /etc/shadow (in Linux). 
"""

import databset # an sqlite wrapper for easy database manipulation
import time

db = dataset.connect('sqlite:////etc/typo_shadow.db')
def add_typo_pw(user, pw):
    pass
