from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import os, struct
from pwcryptolib import (HASH_CNT, RandomWSeed, hash256, hmac256, aes1block)
import joblib
from copy import deepcopy
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


def encrypt(_pk_dict, msg):
    """
    @pk_dict (dict): is a dictionary of id->pk, which will be used to encrypt 
                     a message. pk's in the dict can be EccKey or basestring
    @msg (byte string): a message to be encrypted
    """
    # make a semi-deep copy of the pks
    pk_dict = {k: v for k,v in _pk_dict.items()}

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
    pkctx = { 
        hash256(unicode(_id))[:4]: _encrypt_w_one_pk(pk) 
        for _id, pk in pk_dict.items()
    }
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


def decrypt(_sk_dict, ctx):
    """
    @sk_dict (dict): a dictionary of id->sk, it will try from the "first" element
                     via (sk_dict.pop()) and try to decrypt and if fails will use 
                     the next one. Will fail if none of the id belong to the ctx
    @ctx (byte string): decrypts the ciphertext string
    """
    # Don't change the input dictionary
    sk_dict = {k: v for k,v in _sk_dict.items()}

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
    # For debugging
    ctx_sk_ids = pkctx_dict.keys()
    give_sk_ids = [hash256(unicode(_id))[:4] for _id in sk_dict.keys()]
    # End debugging
    for _id, sk in sk_dict.items():
        h_id = hash256(unicode(_id))[:4]
        if h_id not in pkctx_dict: continue
        aes_k = _decrypt_w_one_sk(sk, pkctx_dict[h_id])
        try:
            msg = AES.new(key=aes_k, mode=AES.MODE_EAX, nonce=nonce)\
                     .decrypt_and_verify(ctx, tag)
            failed_to_decrypt = False
            break
        except KeyError:
            print "Wrong key with id: {}".format(_id)
    if failed_to_decrypt:
        raise ValueError("None of the secret keys ({}) could decrypt the "\
                         "ciphertext with keys=({}) (count={})".format(
                             ctx_sk_ids, give_sk_ids, n_pk)
        )
    return msg

def sign(sk, msg):
    signer = DSS.new(sk, 'fips-186-3')
    h = SHA256.new(msg)
    return signer.sign(h)

def verify(pk, msg, sgn):
    if not isinstance(pk, ECC.EccKey):
        pk = ECC.import_key(pk)
    verifier = DSS.new(pk, 'fips-186-3')
    h = SHA256.new(msg)
    try:
        verifier.verify(h, sgn)
        return True
    except ValueError as e:
        print("VerifyFailed: {}".format(e))
        return False

def hash_pw(pw, sa):
    """
    Compute the slow hash of the password
    @pw (bytes): password
    @sa (bytes): salt (must be >= 16 bytes long)
    ## SLOW
    """
    return hash256(PBKDF2(pw, sa, dkLen=16, count=HASH_CNT)) # SLOW

def derive_public_key(pw, sa, for_='encryption'):
    """
    derive the public key from a password (pw) and salt (sa).
    @pw (bytes): password
    @sa (bytes): salt (must be >= 16 bytes long)
    @for_ (string or bytes): denotes what is the key good for.
           Allowed values: ['encryption', 'verify', 'both']
           Though any key is good for both, but the caller shouold ensure, 
           that signing key is not used for encryption and vice-versa.
           **There is no security guarantee provided if a key is used
             for both encrpytion and signing** 
           'both' will return two keys: one for encryption and another for verifying

    @Returns the slow hash of the password, and public key(s) in serialized format 
    """
    keys_for_ = ('encryption', 'verify', 'both')
    assert for_ in keys_for_, \
        "parameter for_ should be one of {}. Got {}".format(keys_for_, for_)
    if for_ != 'both':
        pwhash, ec_elem = _derive_key(pw, sa, for_)
        return pwhash, serialize_pub_key(ec_elem.public_key())
    else:
        pwhash, (ec_elem_enc, ec_elem_sgn) = _derive_key(pw, sa, for_)
        return (pwhash,
                (serialize_pub_key(ec_elem_enc.public_key()),
                 serialize_pub_key(ec_elem_sgn.public_key())))


def derive_secret_key(pw, sa, for_='decryption'):
    """
    Derive the secret keey from the password (pw) and the salt
    Allowed values: ['decryption', 'sign', 'both']
    CAUTION: This returns key as raw objects, cannot be put in any database
    @Returns the slow hash of the password, and ECC element(s).
    If for_ = 'both', the first ECC element is for encryption, and the second 
    one is for 'signing'
    """
    keys_for_ = ('decryption', 'sign', 'both')
    assert for_ in keys_for_, \
        "parameter for_ should be one of {}. Got {}".format(keys_for_, for_)
    return _derive_key(pw, sa, for_)
    
def _derive_key(pw, sa, for_):
    """derives the ECC public key from the password using the salt.
    @pw (byte string): password
    @sa (byte string): salt (must be >= 16 bytes long)
    @for_ (string): allowed values, ('encryption', 'decryption', 
                                     'verify', 'sign', 'both)
    @Returns: the pwhash and one or two ECC element (depending on the for_)
    """
    curve = 'secp256r1' # 
    intermediate_hash = PBKDF2(pw, sa, dkLen=16, count=HASH_CNT) # SLOW
    pwhash = hash256(intermediate_hash) # The last hash to be stored in the cache
    seed_enc = hash256(intermediate_hash, b'encryption|decryption')
    seed_sgn = hash256(intermediate_hash, b'sign|verify')
    prg_enc = RandomWSeed(seed_enc, 1024)
    prg_sgn = RandomWSeed(seed_sgn, 1024)
    if for_ == 'both':
        return (pwhash,
                (ECC.generate(curve=curve, randfunc=prg_enc.get_random_bytes),
                 ECC.generate(curve=curve, randfunc=prg_sgn.get_random_bytes)))
    elif for_ in ('encryption', 'decryption'):
        return pwhash, ECC.generate(curve=curve, randfunc=prg_enc.get_random_bytes)
    elif for_ in ('sign', 'verify'):
        return pwhash, ECC.generate(curve=curve, randfunc=prg_sgn.get_random_bytes)


def serialize_pub_key(pk):
    """
    Returns the serialized public key of the ec_elem
    @pk (ECC.EccKey): The ec_element you got from derive_key
    """
    assert isinstance(pk, ECC.EccKey),\
        "expecting ECC.EccKey instance got ({})".format(type(ECC.EccKey))
    return '{:170s}'.format(pk.export_key(format='OpenSSH'))


def compute_id(pwtypo, salt):
    """
    Computes an ID for pwtypo. 
    @pwtypo (byte string): mistyped (or correct) password
    @salt (byte string): global salt
    """
    h = hmac256(salt, pwtypo)
    return struct.unpack('<I', h[:4])[0]

def compute_id_w_saltctx(pwtypo, sk_dict, saltctx):
    """
    Computes an ID for pwtypo. 
    @pwtypo (byte string): mistyped (or correct) password
    @sk_dict (dict): {id->sk} dict
    @saltctx (byte string): Ciphertext of the salt
    
    Returns an integer ID of the pwtypo
    """
    salt = decrypt(sk_dict, saltctx)
    h = hmac256(salt, pwtypo)
    return struct.unpack('<I', h[:4])[0]




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
