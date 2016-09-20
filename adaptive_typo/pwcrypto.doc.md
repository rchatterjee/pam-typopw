# Multi-password Encryption Scheme
`contact: rahul@cs.cornell.edu`

We are using multiple passwords to encrypt a message, such that any of the valid
passwords can recover the message from the ciphertext. For our purpose the
encryption scheme has to be assymetric. This is often refered to as a
"multi-user" public key encryption scheme.

Here I am documenting the specification the encryption scheme I have implemented
in `pk_pkcrypto.py`. In the first part of the doc shows how we derive the
public-private key pairs from a password. In the second part, we document the
encryption-decryption procedure and ciphertext format used in the
implementation. Please let me know if you find any flaw in the design.


### Symbol Table for functions and varialbes
* `HSlow`: Slow hash, It's SHA-256 with 10,000 iterations
* `H`: Normal SHA-256 with 1 iterations
* `AES`: AES with 256 bit key, though in `pycryptodome` the message block size
  is still 16.


## Key generation from password  
At a high level we will seed the key generation procedure of a public key crypto
system with the proper slow hash of the given password. However, many public key
crypto system requries more random bits than any standard cryptogrpahic hash
function will povide by default. So we need a mechanism to generate large amount
of seeded pseudo random bits, a.k. a pseudo random generators. 

### Creating a PRG from a PRF  
Pseudo random number generators stretches a $l$ bit seed into a stream of random
numbers. A typical example of PRG is C `random.h` library. Cryptographic hash
functions, such as `SHA-256`, are good pseudo random functions (PRF), and they
are by not by default good PRGs. But under the assumption that all bits of
`SHA-256` are hardcore, we can be easily converted it into a PRG. For
construction I prefer to use `HMAC` whenever possible, so that I don't need to
worry about length extension attacks of the hash function.

`s`: Seed, `HMAC`: HMAC with SHA-256  
`G(s) : h0=HMAC(s,0) || h1=HMAC(s,1) || h2=HMAC(s,2) || ...`

Once we have a PRG construction from a seed we can generate public and private
keys from the given password. 

### Deriving public- and private-key pair from a password  
1. Compute slow hash of the password with a random salt (`sa`).
2. Create a PRG seeded with the hash value. 
3. Derive a ECC (Curve: `secP256r1`) key-pair using the PRG. All key pairs look
   like, `(x, xP)`, where `x` is the private key and `xP` is the public key.
\* We can also take the similar approach for generating `RSA` keypair. Checkout
    `pwcryptolib.py` which has both the key generation procedures. 


## Encryption with multiple public keys  
This is a modified El Gamal. We first encrypt the message with a random key
using AES, and then encrypt the key with the public keys.  
*Input*: `[pk_i], m`
1. Generate a random key (`k`, 32-byte long), and encrypt the message `m` with
   AES-EAX mode (authenticated encryption).  This ciphertext looks like `(nonce,
   tag, ctx)`. 
2. Generate a random ECC point `(r, rP)`.
3. For each public key `pk_i`, compute a secret point `pkr_i = pk_i * r`, and then
   a symmetric key from the two components of the secret point.  
   `k_pk_i = H(pkr_i.x || pkr_i.y)`. 
4. Encrypt `k` with cipher AES-CBC, key `k_pk_i` and a *constant* nonce. Say this
   ciphertext is `pkctx_i`.
5. Final output ciphertext `(rP, [pkctx_i], nonce, tag, ctx)`


*Decryption* is done in obvious way. Decrypt `pkctx_i` with `sk_i`, and then use
the decrypted key to decrypt the `ctx`.


*Updating* the ciphertext with different set of public keys could be done in a
more efficient way. But, right now, I am decrypting the ciphertext with one of
the secret keys, and then re-encrypting the message with the new set of public
keys. We might be able to do it smartly, like only re-encrypt the AES key with
new public keys and replace the header `[pkctx_i]` section. 

To improve the efficiency of decryption, all key pairs need to have an
identifiers, such that, encryption writes down the ids in the header of the
ciphertext `[pkctx_i]`, and during decryption only tries to decrypt the portion
of the cipher text that matches the id of the given secret key. For more details
please see `pw_pkcrypto.py:77`. 

## Usage
See `usage_pw_pkcrypto.ipynb` for more (if availble).
```python
from pw_pkcrypto import encrypt, decrypt, derive_public_key, derive_secret_key
import os
pws = ['password01', 'password02', 'password03']
salts = [os.urandom(16) for _ in pws]
pk_dict = {i: derive_public_key(pw, sa)[1] for i, (pw, sa) in enumerate(zip(pws, salts))}
sk_dict = {i: derive_secret_key(pw, sa)[1] for i, (pw, sa) in enumerate(zip(pws, salts))}

msg = 'The secret message!'
c = encrypt(pk_dict, msg)
m1 = decrypt(dict([sk_dict.popitem()]), c)
m2 = decrypt(dict([sk_dict.popitem()]), c)
assert m1==m2
print m1
```

    The secret message!


### TODO
1. The hash functions in `pycryptodome`, does not look like resilient to
   extension attacks. I should write a wrapper over it at some point of
   time. Now, I am trying to be careful about all the usage of hash functions.
2. Improve the `update` function. 
