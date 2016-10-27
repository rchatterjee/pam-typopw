
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pam_typtop.pwcryptolib import (
    HASH_CNT, SALT_LENGTH, 
    hash256, hmac256, aes1block
)
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key_pair():
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def _slow_hash(pw, sa):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=sa,
        iterations=HASH_CNT,
        backend=default_backend()
    )
    key = kdf.derive(pw)
    return key

def verify(pw, sa, h):
    """Verifies if h(pw, sa) == h
    returns k in case it matches, otherwise None.
    """
    k = _slow_hash(pw, sa)
    hprime = hash256(k)
    if h == hprime:
        return k
    else:
        return None

def harden_pw(pw):
    sa = os.urandom(SALT_LENGTH)
    k = _slow_hash(pw, sa)
    h = hash256(k)
    return (sa, k, h)

def _serialize_pk(pk):
    if isinstance(pk, (basestring, bytes)):
        return pk
    elif isinstance(pk, ec.EllipticCurvePrivateKey):
        pk = pk.public_key()
    return pk.public_bytes(
        serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.PKCS8
    )

def _serialize_sk(sk):
    if isinstance(sk, (basestring, bytes)):
        return sk
    else:
        return sk.private_bytes(
            serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8
        )

def _deserialize_sk(sk_s):
    if isinstance(sk_s, (bytes, basestring)):
        return serialization.load_pem_private_key(
            sk_s, password=None, backend=default_backend()
        )

def _deserialize_pk(pk_s):
    if isinstance(pk_s, (bytes, basestring)):
        return serialization.load_pem_public_key(
            pk_s, backend=default_backend()
        )

def encrpyt(m, k):
    """Symmetric encrpyt.
    """
    f = Fernet(k)
    return f.encrypt(m)

def decrpyt(c, k):
    """Symmetric encrpyt.
    """
    f = Fernet(k)
    return f.decrypt(c)

def pkencrypt(m, pk):
    """Public key encrypt"""
    if not isinstance(pk, ec.EllipticCurvePublicKey):
        pk = _deserialize_pk(pk)
    rsk, rpk = generate_key_pair()
    common_key = urlsafe_b64encode(rsk.exchange(ec.ECDH(), pk))
    
