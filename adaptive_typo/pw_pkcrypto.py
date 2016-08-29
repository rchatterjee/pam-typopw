from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
import os, struct
from pwcryptolib import (HASH_CNT, RandomWSeed, hash256, hmac256, aes1block)
import joblib

# All Crypto operation parameters are of length 32 bytes (256 bits)
# However AES block size is ALWAYS 16 bytes. (That's the standard!)

def update_ctx(pk_dict, sk_dict, ctx):
    """
    Update the ciphertext with the keys only in pk_dict. To make sure ctx is 
    decyptable by all the secret keys corresponding to the pk's in pk_dict.
    @pk_dict (dict): is a dictionary of id->pk, which will be used to encrypt 
                     a message.
    @msg (byte string): the underlying message of ctx
    @ctx (byte string): cipher text to be updated
    """
    # Some optimization we can do in this function, if we find it necessary.
    # For now decrypt and re-encrypt.
    # TODO (rahul): Improve this!
    return encrypt(pk_dict, decrypt(sk_dict, ctx))


def encrypt(pk_dict, msg):
    """
    @pk_dict (dict): is a dictionary of id->pk, which will be used to encrypt 
                     a message. pk's in the dict can be EccKey or basestring
    @msg (byte string): a message to be encrypted
    """
    # First AES-128 encrypt the message with a random key
    aes_k = os.urandom(32) # 32 byte = 256 bit

    # IV is not required for EAX mode
    nonce = os.urandom(16) # the key is generated random every time so, small
                           # nonce is OK
    ctx, tag = AES.new(key=aes_k, mode=AES.MODE_EAX, nonce=nonce)\
                  .encrypt_and_digest(msg)
    serialized_msgctx = nonce + tag + ctx

    # In case pks are serialized, convert them to ecc keys
    for k, v in pk_dict.items():
        if not isinstance(v, ECC.EccKey):
            pk_dict[k] = ECC.import_key(v)
    # Now encrypt the key with pks in pk_dict
    assert len(pk_dict)>0
    assert len(set((pk.curve for pk in pk_dict.values())))==1
    sample_pk = pk_dict.values()[0]
    rand_point = ECC.generate(curve=sample_pk.curve)

    # It is always 161 bytes, extra few bytes in case we runinto issues
    serialized_rand_point = serialize_pub_key(rand_point.public_key())
    def _encrypt_w_one_pk(pk):
        if isinstance(pk, basestring):
            pk = ECC.import_key(pk)
        new_point = pk.pointQ * rand_point.d
        ki = hash256(str(new_point.x), str(new_point.y))
        return aes1block(ki, aes_k, op='encrypt') # iv = 32 '0'-s

    # Hash the ids and take first four bytes, just in case ids are too big.
    # CAUTION: this is valid only if the size of pk_dict is <= 65536
    pkctx = { hash256(_id)[:4]: _encrypt_w_one_pk(pk) for _id, pk in pk_dict.items()}
    assert all(map(lambda v: len(v)==32, pkctx.values()))
    serialized_pkctx = ''.join(k+v for k,v in pkctx.items())

    # each id|pkctx is 36 bytes
    assert len(serialized_pkctx) == 36 * len(pk_dict)
    assert len(serialized_rand_point) == 170

    # CTX-format: 
    #   2     4    32     4    32           4     32        170         32    32   var
    # <npks><id1><pkctx1><id2><pkctx2>....<idn><pkctxn><rand_point_pk><nonce><tag><ctx>
    return struct.pack('<I', len(pk_dict)) + \
        serialized_pkctx + \
        serialized_rand_point + \
        serialized_msgctx


def decrypt(sk_dict, ctx):
    """
    @sk_dict (dict): a dictionary of id->sk, it will try from the "first" element
                     via (sk_dict.pop()) and try to decrypt and if fails will use 
                     the next one. Will fail if none of the id belong to the ctx
    @ctx (byte string): decrypts the ciphertext string
    """
    # parse the ctx
    l_unsigned_int = struct.calcsize('<I')
    n_pk, ctx = struct.unpack('<I', ctx[:l_unsigned_int])[0], ctx[l_unsigned_int:]

    # get the pkctxs
    pkctx_dict = {ctx[i:i+4]: ctx[i+4:i+36] \
               for i in range(0, n_pk*36, 36)}
    ctx = ctx[n_pk*36:]
    serialized_random_point, ctx = ctx[:170], ctx[170:]
    nonce, tag, ctx = ctx[:16], ctx[16:32], ctx[32:]
    rand_point = ECC.import_key(serialized_random_point)
    def _decrypt_w_one_sk(sk, pkctx):
        assert isinstance(sk, ECC.EccKey)
        new_point = rand_point.pointQ * sk.d
        ki = hash256(str(new_point.x), str(new_point.y))
        return aes1block(ki, pkctx, op='decrypt')
    msg = ''
    failed_to_decrypt = True
    for _id, sk in sk_dict.items():
        h_id = hash256(_id)[:4]
        if h_id not in pkctx_dict: continue
        aes_k = _decrypt_w_one_sk(sk, pkctx_dict[h_id])
        try:
            msg = AES.new(key=aes_k, mode=AES.MODE_EAX, nonce=nonce)\
                     .decrypt_and_verify(ctx, tag)
            failed_to_decrypt = False
            break
        except ValueError:
            print "Wrong key with id: {}".format(_id)
    if failed_to_decrypt:
        raise ValueError("None of the secret keys could decrypt the ciphertext")
    return msg

def hash_pw(pw, sa):
    """
    Compute the slow hash of the password
    @pw (bytes): password
    @sa (bytes): salt (must be >= 16 bytes long)
    ## SLOW
    """
    return hash256(PBKDF2(pw, sa, dkLen=16, count=HASH_CNT)) # SLOW

def derive_public_key(pw, sa):
    """
    derive the public key from a password (pw) and salt (sa).
    @pw (bytes): password
    @sa (bytes): salt (must be >= 16 bytes long)
    """
    pwhash, ec_elem = _derive_key(pw, sa)
    return pwhash, serialize_pub_key(ec_elem.public_key())


def derive_secret_key(pw, sa):
    """
    Derive the secret keey from the password (pw) and the salt
    CAUTION: This returns key as raw objects, cannot be put in any database
    """
    pwhash, ec_elem = _derive_key(pw, sa)
    return pwhash, ec_elem


def _derive_key(pw, sa):
    """derives the ECC public key from the password using the salt.
    @pw (byte string): password
    @sa (byte string): salt (must be >= 16 bytes long)
    """
    curve = 'secp256r1' # 
    rand_seed = PBKDF2(pw, sa, dkLen=16, count=HASH_CNT) # SLOW
    rand_num_generator = RandomWSeed(rand_seed, 1024)
    pwhash = hash256(rand_seed) # The last hash to be stored in the cache
    ec_elem = ECC.generate(curve=curve, randfunc=rand_num_generator.get_random_bytes)
    return pwhash, ec_elem # ec_elem can be used to find pk or sk. 


def serialize_pub_key(pk):
    """
    Returns the serialized public key of the ec_elem
    @pk (ECC.EccKey): The ec_element you got from derive_key
    """
    assert isinstance(pk, ECC.EccKey),\
        "expecting ECC.EccKey instance got ({})".format(type(ECC.EccKey))
    return '{:170s}'.format(pk.export_key(format='OpenSSH'))


def compute_id(pwtypo, sk_dict, saltctx):
    """
    Computes an ID for pwtypo. 
    @pwtypo (byte string): mistyped (or correct) password
    @sk_dict (dict): {id->sk} dict
    @saltctx (byte string): Ciphertext of the salt
    
    Returns an integer ID of the pwtypo
    """
    salt = decrypt(sk_dict, saltctx)
    h = hmac256(salt, pwtypo)
    return struct.unpack('<I', h[:4])




def _match_hash(i, pw, h, sa):
    if hash_pw(pw, sa)==h:
        return i
    return -1

def match_hashes(pw, hashlist, saltlist):
    """Check parallely which of the hash matches with hash of pw with the
    corresponding salt.
    returns the @index if found else -1
    """
    with joblib.Parallel(n_jobs=4) as parallel:
        ret = filter(
            lambda x: x!= -1,
            parallel(joblib.delayed(_match_hash)(i, pw, h, sa)
                     for i, (h,sa) in enumerate(zip(hashlist, saltlist)))
        )
    assert len(ret)<=1, "There are multiple hashes with the same underlying password"
    if ret:
        return ret[0]
    else:
        return -1
