
from pam_typtop.pw_pkcrypto2 import (
    generate_key_pair, pkencrypt, pkdecrypt,
    encrypt, decrypt
)
import os


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
