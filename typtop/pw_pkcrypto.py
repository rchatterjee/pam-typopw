import os, sys
print(sys.prefix)
for f in ['LD_LIBRARY_PATH', 'LD_LIBRARY']:
    print(f, os.getenv(f, '<none specified>'))


try: # try cryptography
    import cryptography
    # print "Uisng cryptogrpahy.io"
    from typtop.cryptography_pwpkcrypto import *
except ImportError as e:
    # print "Uisng pycryptodome", e
    from typtop.pycryptodome_pwpkcrypto import *
