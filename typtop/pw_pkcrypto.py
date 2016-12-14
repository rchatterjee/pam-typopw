
try: # try cryptography
    import cryptography
    # print "Uisng cryptogrpahy.io"
    from typtop.cryptography_pwpkcrypto import *
except ImportError as e:
    # print "Uisng pycryptodome", e
    from typtop.pycryptodome_pwpkcrypto import *
