
from __future__ import print_function
from pam_typtop.pw_pkcrypto2 import (
    generate_key_pair, pkencrypt, pkdecrypt,
    encrypt, decrypt, hmac256, compute_id,
    serialize_pk, serialize_sk, deserialize_sk,
    deserialize_pk, verify_pk_sk, harden_pw, verify
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
        c = pkencrypt(pk, unicode(m))
        assert pkdecrypt(sk, c) == m
    assert pkdecrypt(sk, unicode(c)) == m

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

def test_compute_id():
    pw = 'asdadf'
    sa = '0'*16
    compute_id(sa, pw)
    
def test_verify_pk_sk():
    pk, sk = generate_key_pair()
    pks = serialize_pk(pk)
    sks = serialize_sk(sk)
    assert verify_pk_sk(pks, sks)
    assert verify_pk_sk(pk, sks)
    assert verify_pk_sk(pks, sk)
    pk1 = deserialize_pk(pks)
    assert verify_pk_sk(pk1, sk)


def test_harden_pw():
    pw = "amar hiyar majhe lukiye chile"
    sa, k, h = harden_pw(pw)
    k1 = verify(pw, sa, h)
    assert k == k1
    k2 = verify(pw[:-1], sa, h)
    assert not k2
    assert k2 != k
