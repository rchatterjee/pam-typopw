
from __future__ import print_function
from pam_typtop.pw_pkcrypto2 import (
    generate_key_pair, pkencrypt, pkdecrypt,
    encrypt, decrypt, hmac256
)
import struct
import os
import pytest

def test_pkencrypt():
    msgs = [
        'aflashdfhaasdfadsf',
        'asdfkjashdflkashld'[:16],
        'The best secret message ever written by any human!!'
    ]
    pk, sk = generate_key_pair()
    for m in msgs:
        c = pkencrypt(pk, m)
        assert pkdecrypt(sk, c) == m

def test_fail_pkencrypt():
    m = 'asdfasdfsadfasdfasdfasdfasdfasdfasd'
    pk, sk = generate_key_pair()
    c = pkencrypt(pk, m).split('||')
    cprime = pkencrypt(pk, m + '1').split('||')
    assert len(c) == 2 and len(cprime) == 2
    c = c[0] + '||' + cprime[1]
    assert pkdecrypt(sk, '||'.join(cprime)) == m + '1'
    with pytest.raises(ValueError) as excinfo:
        pkdecrypt(sk, c)
        print(excinfo)

def test_symencrypt():
    msgs = [
        'aflashdfhaasdfadsf',
        'asdfkjashdflkashld'[:16],
        'The best secret message ever written by any human!!'
    ]
    k = os.urandom(16)
    for m in msgs:
        c = encrypt(k, m)
        assert decrypt(k, c) == m
