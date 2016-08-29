# Multi-password Encryption Scheme
`contact: rahul@cs.cornell.edu`


We are using multiple passwords to encrypt a message, such that any of the valid
passwords can recover the message from the ciphertext.

Here I am documenting the specification the encryption scheme I have implemented
in `pk_pkcrypto.py`. 


### Symbol Table for functions and varialbes
* `HSlow`: Slow hash, It's SHA-256 with 10,000 iterations
* `H`: Normal SHA-256 with 10,000 iterations
* `AES`: AES with 256 bit key, though in `pycryptodome` the message block size
  is still 16.


### Creating a PRG from a PRF
`s`: Seed, `HMAC`: HMAC with SHA-256
`G(s) : h0=HMAC(s,0) || h1=HMAC(s,1) || h2=HMAC(s,2) || ...`


## Deriving public- and private-key pair from a password
1. Compute slow hash of the password with a random salt.
2. Create a PRG seeded with the hash value. 
3. Derive a ECC (Curve: `secP256r1`) key-pair using the PRG. All key pairs look
   like, `(x, xP)`, where `x` is the private key and `xP` is the public key.


## Encryption with multiple public keys
1. Generate a random key (`k`, 32-byte long), and encrypt the message AES-EAX
   mode (authenticated encryption). Call this ciphertext `(nonce, tag, ctx)`.
2. Get a random ECC point `(r, rP)`. 
3. For each public key `pk_i`, compute a secret point `pkr = pk_i * r`, and then a
   symmetric key: `k_pk_i = H(pkr.x |XXX| pkr.y)`.
4. Encrypt `k` with cipher AES-CBC, key `k_pk_i` and *constant* nonce. Say this
   ciphertext is `pkctx_i`.
5. Output `(rP, [pkctx_i]'s, nonce, tag, ctx)


*Decryption* is done in obvious way. Decrypt `pkctx_i` with `sk_i`, and then use
the decrypted key to decrypt the `ctx`.


*Updating* the ciphertext with different set of public keys. Right now, I think
just decrypt with one of the secret key, and then re-encrypt with the new set of
public keys. We might be able to do it smartly, like only re-encrypt the AES key
with new public keys and replace the header `[pkctx_i]` section.


## TODO
1. The hash functions in `pycryptodome`, does not look like resilient to
   extension attacks. I should write a wrapper over it at some point of
   time. Now, I am trying to be careful about all the usage of hash functions.
