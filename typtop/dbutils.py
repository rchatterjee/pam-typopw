
import struct
from typtop.pw_pkcrypto2 import decrypt

def increament_val(dbh, tabname, key, keyf='desc', valuef='data'):
    """
    Increaments the value of the key in tabname purely using sql query.
    final value of key in tabname will be tabname[keyf=key] + 1
    """
    q = "update {tabname} set {valuef}=(select {valuef}+1 from {tabnme} "\
        "where desc=\"{key}\") where {keyf}=\"{key}\"".format(
            tabname=tabname, keyf=keyf, key=key, valuef=valuef
        )
    dbh.query(q)

def decode_decrypt_sym_count(key, ctx):
    """
    Receives the count ctx, decrypts it, decode it from base64
    and than from bytes to int
    """
    count_in_bytes = decrypt(key, ctx)
    # raise error if bigger? TODO
    return struct.unpack('<i',count_in_bytes)[0]
