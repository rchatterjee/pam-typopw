"""
DO NOT USE THIS!
This very lowlevel functions.
More highlevel functions are available in pw_pkcrypto.py
"""
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
import os
import struct

# In production let's make it 10000. 150 millisecond
HASH_CNT = 1000 # Number of hashes to compute one SHA256 takes 15 microsec,

def hash256(*args):
    """short function for Hashing the arguments with SHA-256"""
    assert len(args)>0, "Should give at least 1 message"
    assert all(isinstance(m, (bytes, basestring)) for m in args), \
        "All inputs should be byte string"
    h = SHA256.new(bytes(len(args)) + bytes(args[0]) + bytes(len(args[0])))
    for m in args[1:]:
        h.update(bytes(m)); 
        h.update(bytes(len(m)))
    h.update(bytes(len(args)))
    return h.digest()

def hmac256(secret, m):
    return HMAC.new(key=secret, msg=m, digestmod=SHA256).digest()

def aes1block(key, msg, iv=bytes(bytearray(16)), op='encrypt'):
    """Encrypt oneblock of message with AES-256"""
    assert len(key) in (32,), \
        "Only AES-256 is supported. Key size: {}".format(len(key))
    assert len(msg) == len(key), \
        "Can encrypt only one block of data. len(msg)={}".format(len(msg))
    assert op in ('encrypt', 'decrypt')
    if op=='encrypt':
        return AES.new(key=key, mode=AES.MODE_CBC, iv=iv)\
                  .encrypt(msg)
    else: # for sure op=='decrypt'
        return AES.new(key=key, mode=AES.MODE_CBC, iv=iv)\
                  .decrypt(msg)

class RandomWSeed(object):
    """Generates pseudo-random numbers seeded with a value @seed.
    """
    def __init__(self, seed, buff_limit=10240):
        self.seed_h = hash256(seed)
        self._cnt = 0
        self._buff_limit = buff_limit
        self._rand_buff  = ''
        self._buff_idx = 0
        self._digest_size = len(self._next_hash())

    def _next_hash(self):
        """Append the current hash with new @cnt, and recompute the hash
        as new list of random bytes. The `self._cnt` value acts as delimiter between
        the update calls (to prevent length extension attack).
        """
        self._cnt += 1
        return hmac256(self.seed_h, bytes(self._cnt))

    def get_random_bytes(self, n):
        """Returns n random bytes.
        """
        assert n<self._buff_limit, "You are asking something larger than buffer "\
            "size. Please increase the buffer size."
        if self._buff_idx+n>len(self._rand_buff):
            self._rand_buff = ''.join(
                self._next_hash() for _ in \
                xrange(self._buff_limit/self._digest_size + 1)
            )
            self._buff_idx = 0
        t, self._buff_idx = self._buff_idx, self._buff_idx + n
        return self._rand_buff[t:self._buff_idx]


class PwRSAKey(object):
    """The module is supposed to be the same as simple Crypto.PublicKey.RSA module,
    except the keys are derived from a password. public key is the same as
    2^16+1.  This function is kind of slow, takes about 0.5 sec to generate
    2048-bit keys, and 1.5 sec to generate 4096-bit keys, so be mindful
    about that.
    """
    oid = '1.2.840.113549.1.1.6'
    @staticmethod
    def generate(pw, salt, keysize=2048):
        """Generates a RSA key pair using the randomness derived from pw, salt. 
        """
        rand_seed = PBKDF2(pw, salt, dkLen=16, count=HASH_CNT)
        rand_num_generator = RandomWSeed(rand_seed, keysize*5)
        return RSA.generate(keysize, randfunc=rand_num_generator.get_random_bytes)

    def construct(rsa_components, consistency_check=True):
        return RSA.construct(rsa_components, consistency_check)

    def import_key(extern_key, passphrase=None):
        return RSA.import_key(extern_key, passphrase)


class PwECCKey(object):
    """The module is supposed to be the same as simple
    Crypto.PublicKey.ECC module, except the keys are derived from a
    password. The ECC key generation is significantly faster than RSA
    key generation.

    The curve 'secp256r1' and 'P-256' refer to the same curve,
    pycryptodome only supports one curve.
    """
    oid = '1.2.840.113549.1.2.6'
    @staticmethod
    def generate_from_pw(pw, salt, curve='P-256'):
        """Generates a ECC key pair using the randomness derived from pw, salt. 
        """
        rand_seed = PBKDF2(pw, salt, dkLen=16, count=HASH_CNT)
        rand_num_generator = RandomWSeed(rand_seed, 1024)
        return ECC.generate(curve=curve, randfunc=rand_num_generator.get_random_bytes)

    def generate(pwhash, curve='secp256r1'):
        rand_num_generator = RandomWSeed(pwhash, 1024)
        return ECC.generate(curve=curve, randfunc=rand_num_generator.get_random_bytes)
        
    def construct(rsa_components, consistency_check=True):
        return ECC.construct(rsa_components, consistency_check)

    def import_key(extern_key, passphrase=None):
        return ECC.import_key(extern_key, passphrase)


def encrypt_with_ecc(public_ecc_key, message, nonce=None):
    """Takes elliptic curve isntance (public_ecc_key) and a byte string (message),
    and outputs a ciphertext
    """
    assert isinstance(public_ecc_key, ECC.EccKey),\
        "public_ecc_key should be ECC key. Got {}".format(type(public_ecc_key))
    random_ecc_key = ECC.generate(curve=public_ecc_key.curve)
    new_point = public_ecc_key.pointQ * random_ecc_key.d
    h = SHA256.new(str(new_point.x))
    h.update('XXX' + str(new_point.y)) # 'XXX' is a delimiter
    key = h.digest()
    if not nonce:
        nonce = os.urandom(16)
    aes_engine = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
    ctx, tag = aes_engine.encrypt_and_digest(message)
    # Return: <ephemeral_pub_key>, <nonce>, <ciphertext>, <tag>
    return (random_ecc_key.public_key().export_key(format='OpenSSH'),
            aes_engine.nonce, ctx, tag)


def decrypt_with_ecc(private_ecc_key, random_pubkey_str, nonce, ctx, tag):
    """Takes elliptic curve isntance (private_ecc_key) and a byte string (message),
    and decrypts the ciphertext (ctx) after verifying the tag.
    """
    assert isinstance(private_ecc_key, ECC.EccKey),\
        "private_ecc_key should be ECC key. Got {}".format(type(private_ecc_key))

    # parse the ciphertext
    random_ecc_key = ECC.import_key(random_pubkey_str)
    new_point = random_ecc_key.pointQ * private_ecc_key.d
    h = SHA256.new(str(new_point.x))
    h.update(str(new_point.y))
    key = h.digest()
    if not nonce:
        nonce = os.urandom(16)
    aes_engine = AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
    msg = ''
    try:
        msg = aes_engine.decrypt_and_verify(ctx, tag)
    except ValueError:
        print "The tag verification failed. Means: ciphertext has been tampered or"\
            "key is incorrect" 
    return msg
