from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
import os

class RandomWSeed(object):
    """Generates pseudo-random numbers seeded with a value @seed.
    """
    def __init__(self, seed, buff_limit=10240):
        self._pw_h = SHA256.new(seed)
        self._cnt = 1
        self._buff_limit = buff_limit
        self._rand_buff  = ''
        self._buff_idx = 0

    def _next_hash(self):
        """Append the current hash with new @cnt, and recompute the hash
        as new list of random bytes.
        """
        self._cnt += 1
        self._pw_h.update('%d' % self._cnt)
        return self._pw_h.digest()

    def get_random_bytes(self, n):
        """Returns n random bytes.
        """
        assert n<self._buff_limit, "You are asking something larger than buffer size, "\
            "increase the buffer size"
        if self._buff_idx+n>len(self._rand_buff):
            self._rand_buff = ''.join(self._next_hash() for _ in \
                                      xrange(self._buff_limit/self._pw_h.digest_size + 1))
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
        rand_seed = PBKDF2(pw, salt, dkLen=16, count=10000)
        rand_num_generator = RandomWSeed(rand_seed, keysize*5)
        return RSA.generate(keysize, randfunc=rand_num_generator.get_random_bytes)

    def construct(rsa_components, consistency_check=True):
        return RSA.construct(rsa_components, consistency_check)

    def import_key(extern_key, passphrase=None):
        return RSA.import_key(extern_key, passphrase)


class PwECCKey(object):
    """The module is supposed to be the same as simple Crypto.PublicKey.RSA module,
    except the keys are derived from a password. public key is the same as
    2^16+1.  This function is kind of slow, takes about 0.5 sec to generate
    2048-bit keys, and 1.5 sec to generate 4096-bit keys, so be mindful
    about that.
    """
    oid = '1.2.840.113549.1.1.6'
    @staticmethod
    def generate(pw, salt, keysize=2048):
        """Generates a ECC key pair using the randomness derived from pw, salt. 
        """
        rand_seed = PBKDF2(pw, salt, dkLen=16, count=10000)
        rand_num_generator = RandomWSeed(rand_seed, keysize*5)
        return ECC.generate(curve='secp256r1', randfunc=rand_num_generator.get_random_bytes)

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
    h.update(str(new_point.y))
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
