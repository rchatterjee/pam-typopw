
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import (
    serialization, hashes
)
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pam_typtop.pwcryptolib import (
    HASH_CNT, SALT_LENGTH, 
    hash256, hmac256
)
import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
import struct

def generate_key_pair():
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

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

def verify_pk_sk(pk, sk):
    try:
        if isinstance(sk, (bytes, basestring)):
            sk = deserialize_sk(sk)
        if not isinstance(pk, (bytes, basestring)):
            pk = serialize_pk(pk)
        pkprime = serialize_pk(sk.public_key())
        return pkprime == pk
    except Exception as e:
        print("ERRROR: {}".format(e))
        print("sk: {}\npk:{}".format(sk, pk))
        raise(e)

def verify(pw, sa, h):
    """Verifies if h(pw, sa) == h
    returns k in case it matches, otherwise None.
    """
    sa = urlsafe_b64decode(bytes(sa))
    k = _slow_hash(pw, sa)
    hprime = hash256(k)
    if h == urlsafe_b64encode(hprime):
        return k
    else:
        return None

def harden_pw(pw):
    sa = os.urandom(SALT_LENGTH)
    k = _slow_hash(pw, sa)
    h = hash256(k)
    return (urlsafe_b64encode(sa), k, urlsafe_b64encode(h))

def serialize_pk(pk):
    if isinstance(pk, (basestring, bytes)):
        return pk
    elif isinstance(pk, ec.EllipticCurvePrivateKey):
        pk = pk.public_key()
    return pk.public_bytes(
        serialization.Encoding.PEM, 
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_sk(sk):
    if isinstance(sk, (basestring, bytes)):
        return sk
    else:
        return sk.private_bytes(
            serialization.Encoding.PEM, 
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

def deserialize_sk(sk_s):
    if isinstance(sk_s, (bytes, basestring, unicode)):
        return serialization.load_pem_private_key(
            bytes(sk_s), password=None, backend=default_backend()
        )
    else:
        return sk_s

def deserialize_pk(pk_s):
    if isinstance(pk_s, (bytes, basestring, unicode)):
        return serialization.load_pem_public_key(
            bytes(pk_s), backend=default_backend()
        )
    else:
        return pk_s

def _encrypt(key, plaintext, associated_data=''):
    # Generate a random 96-bit IV.
    iv = os.urandom(12)
    if len(key) not in algorithms.AES.key_sizes:
        key = hash256(key)  # makes it 256-bit
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # associated_data will be authenticated but not encrypted,
    # it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return (iv, ciphertext, encryptor.tag)

def _decrypt(key, iv, ciphertext, tag, associated_data=''):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    if len(key) not in algorithms.AES.key_sizes:
        key = hash256(key)  # makes it 256-bit

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # We put associated_data back in or the tag will fail to verify
    # when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt(k, m):
    """Symmetric encrpyt.
    """
    if not isinstance(m, bytes):
        m = bytes(m)
    iv, ctx, tag = _encrypt(k, m)
    return urlsafe_b64encode(iv + ctx + tag)

def decrypt(k, ctx):
    """Symmetric decrpyt.
    """
    if not isinstance(ctx, bytes):
        ctx = bytes(ctx)
    ctx_bin = urlsafe_b64decode(bytes(ctx))
    iv, c, tag = ctx_bin[:12], ctx_bin[12:-16], ctx_bin[-16:]
    try:
        return _decrypt(k, iv, c, tag)
    except Exception as e:
        print(e)
        raise(ValueError(e))

def pkencrypt(pk, m):
    """Public key encrypt"""
    if not isinstance(pk, ec.EllipticCurvePublicKey):
        pk = deserialize_pk(pk)
    rpk, rsk = generate_key_pair()
    common_key = rsk.exchange(ec.ECDH(), pk)
    c = encrypt(common_key, m)
    rpk_s = serialize_pk(rpk)
    return '||'.join((rpk_s, c))

def pkdecrypt(sk, ctx):
    """Public key decrypt"""
    if isinstance(sk, (bytes, basestring)):
        sk = deserialize_sk(sk)
    rpk_s, c = ctx.split('||')
    rpk = deserialize_pk(rpk_s)
    common_key = sk.exchange(ec.ECDH(), rpk)
    m = decrypt(common_key, c)
    return m

def compute_id(salt, pwtypo):
    """
    Computes an ID for pwtypo. 
    @pwtypo (byte string): mistyped (or correct) password
    @salt (byte string): global salt
    """
    if len(salt)>SALT_LENGTH:
        salt = urlsafe_b64decode(bytes(salt))
    assert len(salt) == SALT_LENGTH, "len(salt)={} ({})"\
        .format(len(salt), SALT_LENGTH)
    h = hmac256(salt, bytes(pwtypo))
    return struct.unpack('<I', h[:4])[0]

def encrpyt_sk(key, sk):
    if not isinstance(sk, (bytes, basestring)):
        sk = serialize_sk(sk)
    return encrypt(key, sk)
