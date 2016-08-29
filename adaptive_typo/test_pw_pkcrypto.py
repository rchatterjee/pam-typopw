from Crypto.PublicKey import ECC
import os
from pw_pkcrypto import (
    encrypt, decrypt, derive_public_key,
    derive_secret_key, serialize_pub_key,
    compute_id
)

def test_functionality():
    # generate a set of pk,sk pairs
    list_keys = {
        i: ECC.generate(curve='P-256')
        for i in xrange(10)
    }
    pk_dict = {k: v.public_key() for k,v in list_keys.items()}
    msg = 'HI Multiuser! in (test_functionality)'
    ctx = encrypt(pk_dict, msg)
    while list_keys:
        sk_dict = dict([list_keys.popitem()])
        _msg = decrypt(sk_dict, ctx)
        assert msg == _msg, "\n_msg={}\n msg={}\n".format(_msg, msg)

def test_derive_key():
    pw = 'thebest ever secret'
    sa = '12345678'*2
    h1, pk = derive_public_key(pw, sa)
    h2, sk = derive_secret_key(pw, sa)
    assert h1 == h2
    assert serialize_pub_key(sk.public_key()) == pk


def test_compute_id():
    pwtypo = 'asdfadsfadf'
    list_keys = {
        i: ECC.generate(curve='P-256')
        for i in xrange(10)
    }
    pk_dict = {k: v.public_key() for k,v in list_keys.items()}
    salt = os.urandom(32)
    saltctx = encrypt(pk_dict, salt)
    id1 = compute_id(pwtypo, dict([list_keys.popitem()]), saltctx)
    id2 = compute_id(pwtypo, dict([list_keys.popitem()]), saltctx)
    assert id1 == id2
