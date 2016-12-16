
import struct
from typtop.pw_pkcrypto import decrypt
import logging
from config import DB_NAME
import pwd


def isuser(u):
    try:
        pwd.getpwnam(u)
        return True
    except KeyError:
        return False

logger = logging.getLogger(DB_NAME)
def setup_logger(logfile_path, debug_mode, user):
    log_level = logging.DEBUG if debug_mode else logging.INFO
    logger.setLevel(log_level)
    if not logger.handlers:  # if it doesn't have an handler yet:
        handler = logging.FileHandler(logfile_path)
        formatter = logging.Formatter(
            '%(asctime)s:%(levelname)s:<{}>:[%(filename)s:%(lineno)s'\
            '(%(funcName)s)>> %(message)s'.format(user)
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

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

def find_one(table, key, apply_type=str):
    """Finds a key from the table with column name 'desc', and value in
    'data'. It is faster than traditional find_one of 'dataset'.

    """
    # q = 'select data from {} where desc="{}" limit 1'.format(
    #     table.table.name, key
    # )
    # res = ''
    return apply_type(table.get(key, ''))


def decode_decrypt_sym_count(key, ctx):
    """
    Receives the count ctx, decrypts it, decode it from base64
    and than from bytes to int
    """
    count_in_bytes = decrypt(key, ctx)
    # raise error if bigger? TODO
    return struct.unpack('<i',count_in_bytes)[0]
