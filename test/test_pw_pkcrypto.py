from Crypto.PublicKey import ECC
import os
from adaptive_typo.pw_pkcrypto import (
    encrypt, decrypt, derive_public_key,
    derive_secret_key, serialize_pub_key,
    compute_id, hash_pw, match_hashes,
    compute_id_w_saltctx, sign, verify
)

def test_hash_pw():
    pw = 'asdfasfasdfasdf'
    sa = 'asdfasdfasdfasdf'[:16]
    pwhash_h = hash_pw(pw, sa)
    pwhash, pk = derive_public_key(pw, sa)
    assert pwhash_h == pwhash
    pwhash_enc, pk_enc = derive_public_key(pw, sa, for_='encryption')
    pwhash_sgn, pk_sgn = derive_public_key(pw, sa, for_='verify')
    pwhash_both, pk_both = derive_public_key(pw, sa, for_='both')
    assert len(set((pwhash_enc, pwhash_sgn, pwhash_both, pwhash))) == 1
    assert pk_enc == pk
    assert pk_enc == pk_both[0]
    assert pk_sgn == pk_both[1]
    assert pk_enc != pk_sgn


def test_match_hashes():
    salts = [os.urandom(16) for _ in xrange(10)]
    pws = [os.urandom(10) for _ in xrange(10)]
    hashes = [hash_pw(pw, sa) for pw,sa in zip(pws, salts)]
    i = 4
    assert match_hashes(pws[i], hashes, salts)==i

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

def test_encrypt_with_string_keys():
    pw = 'aflashdfhaasdfadsf'
    sa = 'asdfkjashdflkashld'[:16]
    m = 'The best secret message'
    pwhash, pk = derive_public_key(pw, sa)
    pwhash_, sk = derive_secret_key(pw, sa)
    assert decrypt({'abc': sk}, encrypt({'abc': pk}, m)) == m
    
def test_derive_key():
    pw = 'thebest ever secret'
    sa = '12345678'*2
    h1, pk = derive_public_key(pw, sa)
    h2, sk = derive_secret_key(pw, sa)
    assert h1 == h2
    assert serialize_pub_key(sk.public_key()) == pk

def test_sign_verify():
    pw = 'AsUsual the most secure password'
    sa = 'somesalt00112233'
    m = 'The message that I want to sign'
    pwhash1, pk = derive_public_key(pw, sa, for_='verify')
    pwhash2, sk = derive_secret_key(pw, sa, for_='sign')
    assert pwhash1 == pwhash2
    assert verify(pk, m, sign(sk, m))

    pwhash1, (pk_enc, pk_sgn) = derive_public_key(pw, sa, for_='both')
    pwhash2, (sk_enc, sk_sgn) = derive_secret_key(pw, sa, for_='both')
    assert pwhash1 == pwhash2
    assert verify(pk_sgn, m, sign(sk_sgn, m))
    assert verify(pk_enc, m, sign(sk_enc, m))
    assert not verify(pk_sgn, m, sign(sk_enc, m))


def test_compute_id_w_saltctx():
    pwtypo = 'asdfadsfadf'
    list_keys = {
        i: ECC.generate(curve='P-256')
        for i in xrange(10)
    }
    pk_dict = {k: v.public_key() for k,v in list_keys.items()}
    salt = os.urandom(32)
    saltctx = encrypt(pk_dict, salt)
    id1 = compute_id_w_saltctx(pwtypo, dict([list_keys.popitem()]), saltctx)
    id2 = compute_id_w_saltctx(pwtypo, dict([list_keys.popitem()]), saltctx)
    assert isinstance(id1, int)
    assert id1 == id2

def test_compute_id():
    pwtypo = 'asdfadsfadf'
    list_keys = {
        i: ECC.generate(curve='P-256')
        for i in xrange(10)
    }
    pk_dict = {k: v.public_key() for k,v in list_keys.items()}
    salt = os.urandom(32)
    saltctx = encrypt(pk_dict, salt)
    id1 = compute_id(pwtypo, salt)
    id2 = compute_id(pwtypo, salt)
    id3 = compute_id_w_saltctx(pwtypo, dict([list_keys.popitem()]), saltctx)
    assert isinstance(id1, int)
    assert id1 == id2
    assert id1 == id3
    
test_functionality()
