from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
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

