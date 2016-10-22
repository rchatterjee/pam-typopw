import logging
import os
import time
import json
import pwd
import struct
import binascii
from random import random
import dataset
from zxcvbn import password_strength
from pam_typtop.pw_pkcrypto import (
    encrypt, decrypt, derive_public_key,
    derive_secret_key, compute_id,
    sign, verify,
    encrypt_symmetric, decrypt_symmetric
)
from word2keypress import distance

VERSION = "1.0"
DB_NAME = ".typoToler"
ORIG_PW = 'OriginalPw'
SEC_DB_PATH = '/etc/pam_typtop'
SEC_DB_NAME = DB_NAME + ".ro" # READ_ONLY // ROOT_ONLY

ORIG_SK_SALT = 'OriginalPwSaltForEncSecretKey'
ORIG_PW_CTX = 'OrignalPwCtx'
ORIG_PW_ENTROPY_CTX = 'OrgignalPwEntropyCtx'
GLOBAL_SALT_CTX = 'GlobalSaltCtx'
ORIG_PW_ID = 'OrgPwID'
ORIG_PW_ENC_PK = 'EncPublicKey'
ORIG_PW_SGN_PK = 'SgnPublicKey'
ORIG_SGN_SALT = 'OriginalPwSaltForVerifySecretKey'
REL_ENT_BIT_DEC_ALLOWED = "RelativeEntropyDecAllowed"
LOWEST_ENT_BIT_ALLOWED = "LowestEntBitAllowed"
COUNT_KEY_CTX = "CountKeyCtx"

# default values
CACHE_SIZE = 5
EDIT_DIST_CUTOFF = 1
REL_ENT_CUTOFF = -3
LOWER_ENT_CUTOFF = 10
NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED = 30

# Tables' names:
logT = 'Log'
logT_cols = ['id', 'ts', 't_id', 'edit_dist', 'top5fixable', 
             'in_cache', 'allowed_login', 'rel_entropy']

hashCacheT = 'HashCache'
hashCacheT_cols = ['H_typo', 'salt', 'count', 'pk', 'top5fixable']

waitlistT = 'Waitlist'
# table col: base64(enc(json(typo, ts, hash, salt, entropy)))'
auxT = 'AuxSysData' # holds system's setting as well as glob_salt and enc(pw)
# table cols: desc, data
secretAuxSysT = "SecretAuxData"
# table cols: desc, data

# auxiley info 'desc's:
AllowedTypoLogin = "AllowedTypoLogin"
InstallDate = "InstallDate"
InstallationID = "Install_id"
LastSent="Last_sent"
SendEvery="SendEvery(sec)"
UPDATE_GAPS= 24 * 60 * 60 # 24 hours, in seconds
AllowUpload = "AllowedLogUpload"
LoginCount = 'NumOfLogins' # counts logins of real pw only
# - in order to avoid early entry which will change the collected data
# - initiated by typotoler_init. not re-initiated by re-init

SysStatus = "PasswordHasBeenChanged"
CacheSize = "CacheSize"
EditCutoff = "EditCutoff"  # The edit from which (included) it's too far
# PwAcceptPolicy = "PwAcceptPolicy"   # not yet implemented
# LastPwChange = "LastPwChange"  # not yet implemented


rel_bit_strength = 'rel_bit_str'

# GENERAL TODO:
# - improve computation speed
#   - joint hashes/salt computations
#   - more efficent SQL actions

def find_one(table, key, apply_type=str):
    q = 'select data from {} where desc="{}" limit 1'.format(
        table.table.name, key
    )
    try:
        res = list(table.database.query(q))
        return apply_type(res[0]['data'])
    except Exception as e:
        logger.debug('ERROR in db/table: ({}).'.format(table, e))
        return apply_type()

def is_in_top5_fixes(orig_pw, typo):
    return orig_pw in (
        typo.capitalize(), typo.swapcase(), typo.lower(),
        typo.upper(), typo[1:], typo[:-1]
    )

logger = logging.getLogger(DB_NAME)
def setup_logger(logfile_path, log_level):
    logger.setLevel(log_level)
    if not logger.handlers:  # if it doesn't have an handler yet:
        handler = logging.FileHandler(logfile_path)
        formatter = logging.Formatter(
            '%(asctime)s:%(levelname)s:[%(filename)s:%(lineno)s'\
            '(%(funcName)s)>> %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

def encode_encrypt_sym_count(key, count):
    """
    Receives a number, represent it as an interger
    than it encrypts it and encode it in base64
    """
    count_in_bytes = struct.pack('<i', count)
    return binascii.b2a_base64(encrypt_symmetric(count_in_bytes,key))

def decode_decrypt_sym_count(key, ctx):
    """
    Receives the count ctx, decrypts it, decode it from base64
    and than from bytes to int
    """
    count_in_bytes = decrypt_symmetric(bytes(binascii.a2b_base64(ctx)),key)
    return struct.unpack('<i',count_in_bytes)[0] # raise error if bigger? TODO

def encode_encrypt(pk_dict, msg):
    return binascii.b2a_base64(encrypt(pk_dict, msg))

def decode_decrypt(sk_dict, ctx):
    try:
        return decrypt(sk_dict, binascii.a2b_base64(ctx))
    except ValueError as e:
        logger.debug('ctx={!r}, sk_dict={}'.format(ctx, sk_dict))
        logger.debug(e)
        raise(e)

def encode_decode_update(pk_dict, sk_dict, ctx):
    return encode_encrypt(pk_dict, decode_decrypt(sk_dict, ctx))

def get_time_str():
    """
    Returns the timestamp in a string, in a consistent format
    which works in linux and can be stored in the DB
    (unlike datetime.datetime, for example)
    """
    return str(time.time())

def get_time():
    """ returns the time as float since epoch"""
    return time.time()

def get_entropy_stat(typo):
    return password_strength(typo)['entropy']


class UserTypoDB(object):

    class TypoDBError(Exception):
        # all errors that have to do with the typoDB state
        pass
    class NoneInitiatedDB(TypoDBError):
        pass
    class CorruptedDB(TypoDBError):
        pass

    def __str__(self):
        return "UserTypoDB ({})".format(self._user)

    def __init__(self, user, debug_mode=True): # TODO CHANGE to False
        self._user = user  # this is a real user.
        homedir = pwd.getpwnam(self._user).pw_dir
        typo_dir = os.path.join(SEC_DB_PATH, user)
        if not os.path.exists(typo_dir): # creating dir only if it doesn't exist
            # this directory needs root permission, and should be created as
            # part of the installation process
            try:
                os.makedirs(typo_dir)
            except OSError as error:
                print("Trying to create: {}, but seems like the database "
                      "is not initialized.".format(typo_dir))
                raise(error)
        self._db_path = "{}/{}.db".format(homedir, DB_NAME)
        self._sec_db_path="{}/{}.db".format(typo_dir, SEC_DB_NAME) #
        self._log_path = "{}/{}.log".format(homedir, DB_NAME)
        self._db = dataset.connect('sqlite:///{}'.format(self._db_path))
        _sec_db = dataset.connect('sqlite:///{}'.format(self._sec_db_path)) #
        self._sec_tab = _sec_db.get_table(
            secretAuxSysT, 
            primary_id='desc', 
            primary_type='String(100)'
        )
        # only will be available if correct pw is provided
        self._global_salt = None
        # setting the logger object
        log_level = logging.DEBUG if debug_mode else logging.INFO
        setup_logger(self._log_path, log_level)

        dataLine_N = self._get_from_secdb(CacheSize, int)
        if dataLine_N:
            self.N = dataLine_N
            logger.info("{}: N={}".format(hashCacheT, self.N))
        else:
            self.N = CACHE_SIZE

        dataLine_IsON = self._get_from_secdb(AllowedTypoLogin)
        if dataLine_IsON == 'True':
            self.isON, active = True, "ON"
        else:
            self.isON, active = False, "OFF"
        logger.info("typoToler is {}".format(active))

    def getdb(self):
        return self._db

    def get_db_path(self):
        return self._db_path

    def get_logging_path(self, username):
        homedir = pwd.getpwnam(username).pw_dir
        return "{}/{}.log".format(homedir, DB_NAME)

    def is_typotoler_init(self):
        """
        Returns whether the typotoler has been set (might be installed
        but not active)
        """
        encPw = self.get_from_auxtdb(ORIG_PW_CTX)
        globSalt = self.get_from_auxtdb(GLOBAL_SALT_CTX)
        if ((not globSalt) != (not encPw)):
            # if globSalt and pw aren't in the same initialization state
            if not globSalt:
                stub = 'global salt is missing'
            else:
                stub = 'pw is missing'
            logger.critical('DB is corrupted: {}'.format(stub))
            raise UserTypoDB.CorruptedDB(
                "{} is corrupted!  globSalt={}  encPw={}"\
                .format(auxT, globSalt, encPw)
            )
        sgnPk = self._get_from_secdb(ORIG_PW_SGN_PK)
        # if typoToler is initiates, it has both the normal AuxT and
        # the secure table
        return (bool(encPw) and bool(sgnPk))

    def allow_login(self, allow=True):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB(
                "allow_login: Typotoler DB wasn't initiated yet!"
            )
        assert allow in (True, False, 0, 1), "Expects a boolean"
        allow = True if allow else False
        self._sec_tab.update(
            dict(desc=AllowedTypoLogin, data=str(allow)),
            ['desc']
        )
        self.isON = allow
        state = "ON" if allow else "OFF"
        logger.info("typoToler set to {}".format(state))

    def is_allowed_login(self):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB(
                "is_allowed_login: Typotoler DB wasn't initiated yet!"
            )
        is_on = self._get_from_secdb(AllowedTypoLogin)
        assert is_on in ('True', 'False'), \
            'Corrupted data in {}: {}={}'.format(auxT, AllowedTypoLogin, is_on)
        return is_on == 'True'

    def init_typotoler(self, pw, N=CACHE_SIZE, maxEditDist=1, typoTolerOn=False):
        """Create the 'typotoler' database in user's home-directory.  Changes
        the DB permission to ensure its only readable by the user.
        Also, it intializes the required tables as well as the reuired
        variables, such as, the hashCache size, the global salt etc.

        """
        logger.info("Initiating typoToler db with {}".format(
            dict(pw=pw, N=N, maxEditDist=maxEditDist, typoTolerOn=typoTolerOn)
        ))
        u_data = pwd.getpwnam(self._user)
        u_id, g_id = u_data.pw_uid, u_data.pw_gid
        db_path = self._db_path
        sec_db_path = self._sec_db_path
        os.chown(db_path, u_id, g_id)  # change owner to user
        os.chmod(db_path, 0600)  # RW only for owner
        os.chown(sec_db_path,0,0)
        os.chmod(sec_db_path,0644) # RW for root, R for others
        logger.debug(
            "{} permissons set to RW only for user:{}"\
            .format(db_path, self._user)
        )
        log_path = self._log_path
        os.chown(log_path, u_id, g_id)  # change owner to user
        os.chmod(log_path, 0600)  # RW only for owner

        db = self._db
        db[auxT].delete()         # make sure there's no old unrelevent data
        db[hashCacheT].delete()
        db[waitlistT].delete()
        # doesn't delete log because it will also be used
        # whenever a password is changed
        self._sec_tab.delete() #

        # *************** Initializing Aux Data *************************
        install_id = binascii.b2a_base64(os.urandom(8))
        install_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        last_sent_time = get_time()

        logger.info("Initializing the auxiliary data base ({})".format(auxT))
        db[auxT].insert_many([
            dict(desc=InstallationID, data=install_id),
            dict(desc=InstallDate, data=install_time),
            dict(desc=LastSent, data=str(last_sent_time)),
            dict(desc=SendEvery, data=str(UPDATE_GAPS)),
            dict(desc=SysStatus, data=str(0)),
            dict(desc=LoginCount, data=str(0)) ##
        ])
        self.N = N
        self.isON = typoTolerOn

        # *************** add org password, its' pks && global salt: ********

        # 1. derive public_key from the original password
        enc_pk_salt = os.urandom(16) # salt of enc_pk
        global_hmac_salt = os.urandom(16) # global salt

        enc_salt_bs64 = binascii.b2a_base64(enc_pk_salt)
        pw_hash, pw_enc_pk = derive_public_key(pw, enc_pk_salt, for_='encryption')
        pw_id = compute_id(pw, global_hmac_salt)
        enc_pk_dict = {pw_id: pw_enc_pk}

        # TODO CHANGE -- use the same salt for both of them
        # 1.5 inserting pks to the table (with their salts?)
        sgn_pk_salt = os.urandom(16)
        sgn_salt_bs64 = binascii.b2a_base64(sgn_pk_salt)
        _, pw_sgn_pk = derive_public_key(pw, sgn_pk_salt, for_='verify')

        # 2. encrypt the global salt with the enc pk
        global_salt_cipher = binascii.b2a_base64(
            encrypt(enc_pk_dict, global_hmac_salt)
        )

        pw_entropy = encode_encrypt(enc_pk_dict, bytes(get_entropy_stat(pw)))
        pw_cipher = encode_encrypt(enc_pk_dict, pw)
        count_key = os.urandom(16)
        count_key_ctx = encode_encrypt(enc_pk_dict,count_key)


        info_t = db[auxT] #
        info_t.insert_many([
            dict(desc=GLOBAL_SALT_CTX, data=global_salt_cipher),
            dict(desc=ORIG_PW_CTX, data=pw_cipher),
            dict(desc=ORIG_PW_ENTROPY_CTX, data=pw_entropy),
            dict(desc=COUNT_KEY_CTX, data=count_key_ctx)
        ])
        info_t.create_index(['desc']) # To speed up the queries to the table
        # 2.5
        # note - we can't move any ctx to the 'read-only' pk_salt_t
        # because all ctx needs updating everytime a new typo enters HashCache

        self._sec_tab.insert_many([
            dict(desc=ORIG_PW_ID, data=str(pw_id)),
            dict(desc=ORIG_SK_SALT, data=enc_salt_bs64),
            dict(desc=ORIG_PW_ENC_PK, data=pw_enc_pk),
            dict(desc=EditCutoff, data=str(maxEditDist)),
            dict(desc=ORIG_SGN_SALT, data=sgn_salt_bs64),
            dict(desc=ORIG_PW_SGN_PK, data=pw_sgn_pk),
            dict(desc=REL_ENT_BIT_DEC_ALLOWED, data=str(REL_ENT_CUTOFF)),
            dict(desc=LOWEST_ENT_BIT_ALLOWED, data=str(LOWER_ENT_CUTOFF)),
            dict(desc=CacheSize, data=str(N)),
            dict(desc=AllowedTypoLogin, data=str(typoTolerOn)),
            dict(desc=AllowUpload, data='True')
        ])
        self._sec_tab.create_index(['desc'])

        self.set_status('0') #sets status to init

        # 3.
        # Filling the HashCache with garbage
        logger.debug("Filling HashCache with garbage")
        garbage_list = []
        _, pw_sgn_sk = derive_secret_key(pw, sgn_pk_salt, for_='sign')
        for i in range(self.N):
            g_salt = os.urandom(16)
            g_salt_bs64 = binascii.b2a_base64(g_salt)
            garb = os.urandom(20)
            g_edit_dist = 1
            isTop5 = ord(os.urandom(1)[0]) % 2
            g_count = -(ord(os.urandom(1)[0]))
            # print "key,key_l: {},{}".format(count_key,len(count_key)) #
            # TODO REMOVE
            ctx_count_bs64 = encode_encrypt_sym_count(count_key,g_count)
            garb_h,garb_pk = derive_public_key(garb, g_salt)
            garb_h_bs64 = binascii.b2a_base64(garb_h)
            sgn_hash = sign(pw_sgn_sk, (garb_h_bs64+garb_pk).encode('utf-8'))
            sgn_hash_b64 = binascii.b2a_base64(sgn_hash)
            # sign the pk TODO
            garbage_list.append(dict(
                H_typo = garb_h_bs64,
                salt = g_salt_bs64,
                count = ctx_count_bs64,
                pk = garb_pk,
                top5fixable = isTop5,
                sign = sgn_hash_b64,
                edit_dist = g_edit_dist))

        self._db[hashCacheT].insert_many(garbage_list)

        logger.debug("Initialization Complete")

    def update_after_pw_change(self, newPw):
        """
        Re-initiate the DB after a pw change.
        Most peripherial system settings don't change, including installID
        generates a new hmac salt,
        and encrypts the new pw, pw_ent, and the hmac salt
        """
        # **************  ATTENTION ! *******************************
        # MOSTALY a simple copy-paste of steps 1 to 2.5
        # needs updating if we change them
        logger.info("Re-intializing after a pw change")
        db = self._db
        info_t = db[auxT] #

        # 1. derive public_key from the original password
        enc_pk_salt = os.urandom(16) # salt of enc_pk
        global_hmac_salt = os.urandom(16) # global salt

        enc_salt_bs64 = binascii.b2a_base64(enc_pk_salt)
        pw_hash, pw_enc_pk = derive_public_key(newPw, enc_pk_salt, for_='encryption')
        pw_id = compute_id(newPw, global_hmac_salt)
        enc_pk_dict = {pw_id: pw_enc_pk}

        # 1.5 inserting pks to the table (with their salts?)
        sgn_pk_salt = os.urandom(16)
        sgn_salt_bs64 = binascii.b2a_base64(sgn_pk_salt)
        _, pw_sgn_pk = derive_public_key(newPw, sgn_pk_salt, for_='verify')

        # 2. encrypt the global salt with the enc pk
        global_salt_cipher = binascii.b2a_base64(encrypt(enc_pk_dict, global_hmac_salt))

        pw_entropy = encode_encrypt(enc_pk_dict, bytes(get_entropy_stat(newPw)))
        pw_cipher = encode_encrypt(enc_pk_dict, newPw)
        count_key = os.urandom(16)
        count_key_ctx = encode_encrypt(enc_pk_dict,count_key)

        info_t.update(dict(desc=GLOBAL_SALT_CTX, data=global_salt_cipher), ['desc'])
        info_t.update(dict(desc=ORIG_PW_CTX, data=pw_cipher), ['desc'])
        info_t.update(dict(desc=ORIG_PW_ENTROPY_CTX, data=pw_entropy), ['desc'])
        info_t.update(dict(desc=COUNT_KEY_CTX, data=count_key_ctx),['desc']) #


        # 2.5
        # note - we can't move any ctx to the 'read-only' self._sec_tab
        # because all ctx needs updating everytime a new typo enters HashCache
        self._sec_tab.update(dict(desc=ORIG_PW_ID, data=str(pw_id)), ['desc'])
        self._sec_tab.update(dict(desc=ORIG_SK_SALT, data=enc_salt_bs64), ['desc'])
        self._sec_tab.update(dict(desc=ORIG_PW_ENC_PK, data=pw_enc_pk), ['desc'])
        self._sec_tab.update(dict(desc=ORIG_SGN_SALT, data=sgn_salt_bs64), ['desc'])
        self._sec_tab.update(dict(desc=ORIG_PW_SGN_PK, data=pw_sgn_pk), ['desc'])


        # 3 sending logs and deleting tables:
        logger.debug('Sending logs')
        self.update_last_log_sent_time(get_time(), True)

        logger.debug("Deleting tables")
        db[hashCacheT].delete()
        db[waitlistT].delete()
        db[logT].delete()

        # Filling the HashCache with garbage
        logger.debug("Filling HashCache with garbage")
        garbage_list = []
        _, pw_sgn_sk = derive_secret_key(newPw, sgn_pk_salt, for_='sign')
        for i in range(self.N):
            g_salt = os.urandom(16)
            g_salt_bs64 = binascii.b2a_base64(g_salt)
            garb = os.urandom(20)
            g_edit_dist = 1
            isTop5 = ord(os.urandom(1)[0]) % 2
            g_count = -(ord(os.urandom(1)[0]))
            # print "key,key_l: {},{}".format(count_key,len(count_key)) #
            # TODO REMOVE
            ctx_count_bs64 = encode_encrypt_sym_count(count_key,g_count)
            garb_h,garb_pk = derive_public_key(garb, g_salt)
            garb_h_bs64 = binascii.b2a_base64(garb_h)
            sgn_hash = sign(pw_sgn_sk, (garb_h_bs64+garb_pk).encode('utf-8'))
            sgn_hash_b64 = binascii.b2a_base64(sgn_hash)
            # sign the pk TODO
            garbage_list.append(dict(
                H_typo = garb_h_bs64,
                salt = g_salt_bs64,
                count = ctx_count_bs64,
                pk = garb_pk,
                top5fixable = isTop5,
                sign = sgn_hash_b64,
                edit_dist = g_edit_dist))

        self._db[hashCacheT].insert_many(garbage_list)

        self.set_status('0') #sets status to init

        logger.info("RE-Initialization Complete")

    def get_count_key(self, sk_dict):
        key_ctx = self.get_from_auxtdb(COUNT_KEY_CTX)
        return bytes(decode_decrypt(sk_dict, key_ctx))

    def get_installation_id(self):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB("Typotoler uninitialized")
        return self.get_from_auxtdb(InstallationID)

    def get_last_unsent_logs_iter(self):
        """
        Check what was the last time the log has been sent,
        And returns whether the log should be sent
        """
        logger.debug("Getting last unsent logs")
        if not self.is_typotoler_init():
            logger.debug("Could not send. Typotoler not initiated")
            return False, iter([])
        upload_status = self._get_from_secdb(AllowUpload)
        if not upload_status:
            raise UserTypoDB.CorruptedDB("Missing {} in {}".format(
                AllowUpload, secretAuxSysT))
        if upload_status != 'True':
            logger.info("Not sending logs because send status set to {}".format(
                upload_status))
            return False, iter([])
        last_sending = self.get_from_auxtdb(LastSent, float)
        update_gap = self.get_from_auxtdb(SendEvery, float)
        time_now = time.time()
        passed_enough_time = ((time_now - last_sending) >= update_gap)
        if not passed_enough_time:
            logger.debug("Last sent time:{}".format(str(last_sending)))
            logger.debug("Not enought time has passed to send new logs")
            return False, iter([])
        log_t = self._db[logT]
        new_logs = log_t.find(log_t.table.columns.ts >= last_sending)
        logger.info("Prepared new logs to be sent, from {} to {}".format(
            str(last_sending), str(time_now))
        )
        return True, new_logs

    def update_last_log_sent_time(self, sent_time=0, delete_old_logs=False):
        logger.debug("updating log sent time")
        if not sent_time:
            sent_time = get_time()
            logger.debug("generating new timestamp={} ".format(sent_time))
        self._db[auxT].update(dict(
            desc=LastSent, data=float(sent_time)), ['desc']
        )
        if delete_old_logs:
            logger.debug("deleting old logs")
            log_t = self._db[logT]
            log_t.table.delete().where(
                log_t.table.columns.ts <= float(sent_time)
            ).execute()

    def allow_upload(self, allow):
        upload_status = 'True' if allow else 'False'
        self._sec_tab.upsert(
            dict(desc=AllowUpload,data=upload_status),
            ['desc']
        )
        assert isinstance(allow, bool)
        self.isON = allow

    def is_allowed_upload(self):
        send_stat_row = self._get_from_secdb(AllowUpload)
        return send_stat_row == 'True'

    def _hmac_id(self, typo, sk_dict):
        """
        Calculates the typo_id required for logging.
        @typo (string) : the typo
        @sk_dict (dict) : is a dictionar from t_h_id -> ECC secret_key,
        """
        global_salt = self.get_global_salt(sk_dict)
        logger.debug("Got global salt") # TODO REMOVE
        typo_id = compute_id(bytes(typo.encode('utf-8')), global_salt)
        return typo_id

    def fetch_from_cache(self, typo, increaseCount=True, updateLog=True):
        '''Returns possible sk_dict, and whether the typo found in the cache
        By default:
            - increase the typo count
            - write the relevant log

        we removed the typo_id from the hashCache for security reasons so it (as
        well as the difference in entropy) needs to be calculated every time -
        only if it is actually found

        @typo (string) : the given password typo
        @increaseCount (bool) : whether to update the typo's count if found
        @updateLog (bool) : whether to insert an update to the log

        '''
        logger.debug("Searching for typo in {}".format(hashCacheT))
        # getting the pw's verify pk
        sgn_pk = self._get_from_secdb(ORIG_PW_SGN_PK)
        logger.debug("found signing key:{}".format(sgn_pk))

        cacheT = self._db[hashCacheT]
        for cacheline in cacheT:
            sa = binascii.a2b_base64(cacheline['salt'])
            hs_bytes, sk = derive_secret_key(typo, sa)

            t_h_id = cacheline['H_typo'] # the hash id is in base64 form
            sgn = binascii.a2b_base64(cacheline['sign']) #
            t_pk = cacheline['pk'] # the pk is a string
            # verifing the integrity of the hash data and the pk 
            # unverified data in DB
            if not verify(bytes(sgn_pk), bytes(t_h_id + t_pk), sgn):
                err_msg = "Unverified hash in {}. Sign:{}, Hash:{}".format(
                    hashCacheT, sgn, t_h_id)
                logger.critical(err_msg)
                raise UserTypoDB.CorruptedDB(err_msg)

            # Check if the hash(typo, sa) matches the stored hash
            # and that it isn't an initial garbage fill
            if binascii.a2b_base64(t_h_id) != hs_bytes: continue #notEq
            sk_dict = {t_h_id: sk}
            count_key = self.get_count_key(sk_dict)
            typo_count = decode_decrypt_sym_count(count_key, cacheline['count'])
            if typo_count <= 0: continue   # garbage

            logger.debug(
                "Typo found in {} (t_h_id={!r})".format(hashCacheT, t_h_id)
            )

            # update table with new count
            if increaseCount:
                cacheT.update(dict(
                    H_typo=t_h_id,
                    count=encode_encrypt_sym_count(count_key, typo_count+1)
                ), ['H_typo'])
            
            if updateLog:
                self.update_log(
                    typo, sk_dict,
                    other_info={
                        'edit_dist': 0,
                        'top5fixable': 0,
                        'in_cache': True,
                        'allowed_login': True,
                        'rel_entropy': 0
                    }
                )
            return sk_dict, True

        logger.debug("Typo wasn't found in {}".format(hashCacheT))
        return {}, False

    def update_log(self, typo, sk_dict={}, other_info={}):
        """Updates the log with information about typo. Remember, if sk_dict is
        not provided it will insert @typo as typo_id and 0 as relative_entropy.
        Note the default values used in other_info, which is basically what
        is expected for the original password.
        """
        other_info['t_id'] = self._hmac_id(typo, sk_dict) if sk_dict else typo
        other_info['ts'] = get_time()

        for col in ('edit_dist', 'top5fixable', 'in_cache',
                    'allowed_login', 'rel_entropy'):
            if col not in other_info:
                other_info[col] = 0

        # The 'id' columns is a unique column that is added to the table
        # automatically in some instances we get a dictionary from another
        # table so we need to delete it in order to avoid clashes
        if 'id' in other_info: # TODO CHANGE to try?
            del other_info['id']

        self._db[logT].insert(other_info)

    def log_orig_pw_use(self):
        ts = get_time()
        pw_id = self._get_from_secdb(ORIG_PW_ID, int)
        self.update_log(pw_id)

    def log_message(self, msg):
        ts = get_time()
        self._db[logT].insert(dict(t_id=msg, timestamp=ts))

    def get_approved_pk_dict(self):
        '''
        Returns a dict of pw'->pk
        for all approved typos and the original pw

        for the typos, the ids are the base64 of their hashes in HashCache
        '''
        pk_dict = {
            cacheline['H_typo']: cacheline['pk']
            for cacheline in self._db[hashCacheT]
        }

        # original pw's pk
        orig_pw_pk = self._get_from_secdb(ORIG_PW_ENC_PK)
        orig_pw_id = self._get_from_secdb(ORIG_PW_ID, int)
        pk_dict[orig_pw_id] = orig_pw_pk #
        assert len(pk_dict)>0, "PK_dict size is zero!!"
        logger.debug("PK_dict keys: {}".format(pk_dict.keys()))
        return pk_dict

    def get_pw_sign_sk(self, pw):
        sgn_salt_bs64 = self._get_from_secdb(ORIG_SGN_SALT)
        sgn_salt = binascii.a2b_base64(sgn_salt_bs64)
        _, pw_sgn_sk = derive_secret_key(pw, sgn_salt, for_='sign')
        return pw_sgn_sk

    def add_typo_to_waitlist(self, typo):
        """
        Adds the typo to the waitlist.
        saves the timestamp as well (for logging reasons)
        **** for now: (might change from computation time reasons) ****
        computes an hash for the typo (+sa)
        encryptes everything in a json format
        enc(json(dict(...)))
        dictionary keys: typo_hs, typo_pk, typo_pk_salt, timestamp, typo

        @typo (string) : the user's passwrod typo
        """
        logger.debug("Adding a new typo to waitlist")
        sa = os.urandom(16)
        typo_hs, typo_pk = derive_public_key(typo, sa)
        ts = get_time()

        typo_entropy = get_entropy_stat(typo)
        plainInfo = json.dumps({
            "typo_hs": binascii.b2a_base64(typo_hs),
            "typo_pk": typo_pk,
            "typo_pk_salt": binascii.b2a_base64(sa),
            "timestamp": ts,
            "typo": typo,
            'typo_ent_str': typo_entropy
        })
        pk_dict = self.get_approved_pk_dict()
        info_ctx = binascii.b2a_base64(encrypt(pk_dict, plainInfo))
        logger.debug("Typo encrypted successfully with key-id: {}"\
                     .format(pk_dict.keys()))
        self._db[waitlistT].insert(dict(ctx=info_ctx))

    def decrypt_waitlist(self, sk_dict):
        '''
        Returns a dictionary of the typos in waitlist, unsorted,
        Key = typo (string)
        Value = (typo, t_count, ts_list, typo_hs, t_pk, t_pk_salt)
        '''
        new_typo_dic = {}
        for line in self._db[waitlistT].all():
            bin_ctx = binascii.a2b_base64(line['ctx'])
            typo_info = json.loads(decrypt(sk_dict, bin_ctx))
            ts = typo_info['timestamp']
            typo = typo_info['typo']
            typo_hs_b64 = typo_info['typo_hs']
            t_pk = typo_info['typo_pk']
            typo_entropy = typo_info['typo_ent_str']
            pk_salt_b64 = typo_info["typo_pk_salt"]
            if typo not in new_typo_dic:
                new_typo_dic[typo] = ([ts], typo_hs_b64, t_pk,
                                      pk_salt_b64, typo_entropy)
            else:
                new_typo_dic[typo][0].append(ts) # appending ts to ts_list

        logger.info("Waitlist decrypted successfully")
        return new_typo_dic

    def get_top_N_typos_within_distance(self, typoDic, pw, pw_entropy,
                                        sk_dict, updateLog=True):
        """
        Gets a dictionary (from waitlist) of all new typos
        calculates their editDistance (in the future isTop5 TODO )
        and returns the top N among them, within the edit distance

        by defaults - update the log retroactively on each entered typo

        @typoDic (dict) - a dictinary of all typos. see "decrypt_waitlist"
                            for foramt
        @pw (string) - the original password
        @t_id, t_sk - an approved typo id and it's sk
        @updateLog (bool) : whether to update the log about each typo
        """
        logger.debug("getting the top N typos within edit distance")

        # getting the signing key of the pw
        sgn_salt_bs64 = self._get_from_secdb(ORIG_SGN_SALT)
        maxEditDist = self._get_from_secdb(EditCutoff, int)

        sgn_salt = binascii.a2b_base64(sgn_salt_bs64)
        _, pw_sgn_sk = derive_secret_key(pw, sgn_salt, for_='sign')

        global_salt = self.get_global_salt(sk_dict)
        typo_list = []

        for typo in typoDic.keys():
            ts_list, t_hs_bs64, typo_pk, t_sa_bs64, typo_ent  = typoDic[typo]
            count = len(ts_list)
            editDist = distance(str(pw), str(typo))
            typo_id = compute_id(bytes(typo.encode('utf-8')), global_salt)
            rel_entropy = typo_ent - pw_entropy

            # writing into log for each ts
            if updateLog:
                for _ in ts_list:
                    self.update_log(
                        typo, sk_dict=sk_dict,
                        other_info={
                            'edit_dist': editDist,
                            'top5fixable': is_in_top5_fixes(pw, typo),
                            'in_cache': False,
                            'allowed_login': False,
                            'rel_entropy': rel_entropy
                        }
                    )

            closeEdit = (editDist <= maxEditDist)
            rel_bound = self._get_from_secdb(REL_ENT_BIT_DEC_ALLOWED, int)
            strict_bound = self._get_from_secdb(LOWEST_ENT_BIT_ALLOWED, int)
            notMuchWeaker = (rel_entropy >= rel_bound)
            notTooWeak = (typo_ent >= strict_bound)

            if closeEdit and notMuchWeaker and notTooWeak:
                sgn_hash = sign(
                    pw_sgn_sk,
                    t_hs_bs64.encode('utf-8') + typo_pk.encode('utf-8')
                )
                sgn_hash_bs64 = binascii.b2a_base64(sgn_hash)
                typo_list.append({
                    'H_typo': t_hs_bs64,
                    'sign': sgn_hash_bs64,
                    'salt': t_sa_bs64,
                    'count': count,
                    'pk': typo_pk,
                    'edit_dist': editDist,
                    'top5fixable': is_in_top5_fixes(pw, typo)
                })
            else:
                logger.debug(
                    "{} not entered because editDist: {} and "
                    "rel_typo_entropy: {}"\
                    .format(typo_id, editDist, rel_entropy)
                )
            # Note - if a typo doesn't enter because of an objective lower
            # bound on the entropy, we do not print it. It can be deduced to
            # be the case if both editDist and relEnt are 0
        return sorted(typo_list, key=lambda x: -x['count'])[:self.N]

    def get_table_size(self, tableName):
        return self._db[tableName].count()

    def get_hash_cache_size(self):
        return self.get_table_size(hashCacheT)

    def get_pw_sk_salt(self):
        sk_salt_base64 = self._get_from_secdb(ORIG_SK_SALT)
        assert sk_salt_base64, \
            "{}[{}] = {!r}. It should not be None."\
                .format(auxT, ORIG_SK_SALT, sk_salt_base64)
        return binascii.a2b_base64(sk_salt_base64)

    def get_orig_pw(self, sk_dict):
        """
        Returns pw, pw's entropy (in bits)
        Mainly used after the user submitted an APPROVED typo,
        and now we need to original pw to calc edit_dist
        and the difference in entropy
        """
        logger.debug("Getting original pw")
        orig_pw = decode_decrypt(
            sk_dict,
            self.get_from_auxtdb(ORIG_PW_CTX)
        )
        orig_pw_entropy = decode_decrypt(
            sk_dict,
            self.get_from_auxtdb(ORIG_PW_ENTROPY_CTX)
        )
        logger.debug("Fetched original password successfully")
        return orig_pw, float(orig_pw_entropy)

    def get_global_salt(self, sk_dict):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        if not self._global_salt:
            try:
                salt_ctx = self.get_from_auxtdb(GLOBAL_SALT_CTX)
                self._global_salt = decode_decrypt(sk_dict, salt_ctx)
            except ValueError as e:
                logging.debug(
                    "Sorry wrong id-sk pair ({}). Couldn't decrypt the salt"\
                    .format(sk_dict)
                )
        return self._global_salt

    # TODO FUTURE
    def cache_insert_policy(self, old_t_c, new_t_c):
        if old_t_c < 0: # for garbage rows in cache
            return True
        chance = float(new_t_c)/(int(old_t_c)+1)
        debug_info =  "the chance is:{}".format(chance)
        rnd = random()
        debug_info += "rnd is:{}".format(rnd)
        logger.debug(debug_info)
        return rnd <= chance

    def get_lowest_M_line_in_hash_cache(self, M):
        # might be slow - and than we should re-write it
        hashT = self._db[hashCacheT]
        result = hashT.find(order_by='count',_limit=M)
        return result

    def add_top_N_typos(self, typo_list, sk_dict):
        # typo list is already sorted in DECRREASING order
        # get count_enc_key TODO
        # decrypt

        cache_t = self._db[hashCacheT]
        count_key = self.get_count_key(sk_dict)

        currently_in_cache = []
        for row in cache_t.all():
            row['count'] = decode_decrypt_sym_count(count_key,row['count'])
            currently_in_cache.append(row)
        currently_in_cache.sort(key=lambda x: x['count'])
        # TODO - make sure it's ordered in INCREASING order
        for ii, typo_d  in enumerate(typo_list):
            h_line_d  = currently_in_cache[ii]
            typo_c = typo_d['count']
            line_c = h_line_d['count']
            if self.cache_insert_policy(line_c, typo_c):
                new_count = (line_c + 1) if (line_c > 0) else typo_c
                typo_d['count'] = encode_encrypt_sym_count(count_key, new_count)
                typo_d['id'] = h_line_d['id'] # the primary col in hashCache
                cache_t.update(typo_d, ['id'])
        # shuffle ? TODO

    def update_aux_ctx(self, sk_dict):
        """
        Assumes that the auxT is ok with both password and global salt
        """
        logger.info("Updating {}".format(auxT))
        infoT = self._db[auxT]
        pk_dict = self.get_approved_pk_dict()
        for field in [ORIG_PW_CTX, GLOBAL_SALT_CTX,
                      ORIG_PW_ENTROPY_CTX, COUNT_KEY_CTX]:
            new_ctx = encode_decode_update(
                pk_dict, sk_dict, self.get_from_auxtdb(field)
            )
            infoT.update(dict(desc=field, data=new_ctx), ['desc'])
        logger.debug("Aux ctx updated successfully: {}".format(len(pk_dict)))

    def clear_waitlist(self):
        self._db[waitlistT].delete()
        logger.info("{} had been deleted".format(waitlistT))

    def update_login_count(self):
        """Keeps track of how many times the user has successfully logged in."""
        count_entry = self.get_from_auxtdb(LoginCount, int) + 1
        self._db[auxT].update(
            dict(desc=LoginCount, data=str(count_entry)), 
            ['desc']
        )

    def original_password_entered(self, pw, updateLog=True):
        if updateLog:
            self.log_orig_pw_use()
        logger.info("Original password had been entered by user")
        pw_salt = self.get_pw_sk_salt()
        logger.debug("Deriving secret key of the password")
        _, pw_sk = derive_secret_key(pw, pw_salt)
        pw_id = self._get_from_secdb(ORIG_PW_ID, int)
        self.update_hash_cache_by_waitlist({pw_id: pw_sk}, pw)

    def _get_from_secdb(self, key, apply_type=str):
        return find_one(self._sec_tab, key, apply_type)

    def get_from_auxtdb(self, key, apply_type=str):
        return find_one(self._db[auxT], key, apply_type)

    def update_hash_cache_by_waitlist(self, sk_dict, typo='', updateLog=True):
        """
        Updates the hash cache according to waitlist.
        It also updates the log accordingly (if updateLog is set)
        and clears waitlist

        @updateLog (bool) : whether to update in the log, set to True
        @typo (string) : if set, then 
        """
        logger.info("Updating {} by {}".format(hashCacheT, waitlistT))
        waitlistTypoDict = self.decrypt_waitlist(sk_dict)
        orig_pw, pw_entropy = self.get_orig_pw(sk_dict)
        if typo != '':
            # making sure the hashCache hadn't been tempered with
            # by making sure the typo is still a legit typo
            # i.e - within edit distance and entropy difference
            editDist = distance(str(orig_pw), str(typo))
            typo_ent = get_entropy_stat(typo)
            rel_entropy = typo_ent - pw_entropy

            rel_bound = self._get_from_secdb(REL_ENT_BIT_DEC_ALLOWED, int)
            strict_bound = self._get_from_secdb(LOWEST_ENT_BIT_ALLOWED, int)
            edist_bound = self._get_from_secdb(EditCutoff, int)

            notMuchWeaker = (rel_entropy >= rel_bound)
            notTooWeak = (typo_ent >= strict_bound)
            closeEdit = (editDist <= edist_bound)
            legit = (notTooWeak and notMuchWeaker and closeEdit)
            if not legit:
                raise UserTypoDB.CorruptedDB(
                    "illegal typo within {}".format(hashCacheT)
                )

        topNList = self.get_top_N_typos_within_distance(
            waitlistTypoDict, orig_pw, pw_entropy, sk_dict, updateLog
        )
        self.add_top_N_typos(topNList, sk_dict)
        # update the ctx of the original password and the global salt
        # because HashCache hash Changed
        self.update_aux_ctx(sk_dict)
        self.clear_waitlist()

    def get_prompt(self):
        # pwd promts
        NOT_INITIALIZED = "(Adaptive typo not initialized) Password"
        ACTIVATED = 'aDAPTIVE pASSWORD'
        RE_INIT = 'Please re-init'
        CORRUPT_DB = "Corrupted DB !"
        ERROR = "Error"
        linePwCh = self.get_from_auxtdb(SysStatus)
        if not linePwCh:
            return NOT_INITIALIZED
        val = int(linePwCh)
        if val == 0:
            return ACTIVATED
        if val == 1:
            return RE_INIT
        if val == 2:
            return CORRUPT_DB
        return ERROR # shouldn't reach here

    def set_status(self, status):
        self._db[auxT].upsert(
            dict(desc=SysStatus, data=str(status)),
            ['desc']
        )

def get_status_dict():
    return dict(active=0,
                after_pw_change=1,
                corrupted_db=2)

def on_correct_password(typo_db, password):
    logger.info("sm_auth: it's the right password")
    # log the entry of the original pwd
    try:
        if not typo_db.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB(
                "ERROR: (on_correct_pass) Typotoler DB wasn't initiated yet!"
            )
            # the initialization is now part of the installation process
        sysStatVal = typo_db.get_from_auxtdb(SysStatus)
        if not sysStatVal: # if not found in table
            raise UserTypoDB.Corrupted(
                "ERROR: (on_correct_password) Typotoler DB is Corrupted."
            )
        if int(sysStatVal) == 1:
            raise KeyError
        if int(sysStatVal) == 2:
            raise UserTypoDB.CorruptedDB("")

        # if reached here - db should be initiated
        # updating the entry count
        typo_db.update_login_count()
        typo_db.original_password_entered(password) # also updates the log
    except UserTypoDB.CorruptedDB as e:
        logger.error("Corrupted DB!")
        typo_db.set_status(2)
        # DB is corrupted, needs restart
    except KeyError as e:
        # most probably - an error of decryption as a result of pw change
        typo_db.set_status(1)
        logger.error("Key error raised. probably a failure in decryption")
        logger.error("details: {}".format(e.message))
    except Exception as e:
        logger.error(
            "Unexpected error while on_correct_password:\n{}\n"\
            .format(e.message)
        )
    # In order to avoid locking out - always return true for correct password
    return True

def on_wrong_password(typo_db, password):
    try:
        sysStatVal = typo_db.get_from_auxtdb(SysStatus)
        if not sysStatVal: # if not found in table
            raise UserTypoDB.NoneInitiatedDB(
                "on_wrong_password: Typotoler DB wasn't initiated yet!"
            )
        if int(sysStatVal) == 1:
            raise KeyError
        if int(sysStatVal) == 2:
            raise UserTypoDB.CorruptedDB("")

        # if reached here - db should be initiated, also updates the log
        sk_dict, is_in = typo_db.fetch_from_cache(password)
        if not is_in: # aka it's not in the cache,
            typo_db.add_typo_to_waitlist(password)
            return False
        else: # it's in cache
            # also updates the log
            typo_db.update_hash_cache_by_waitlist(sk_dict, typo=password)
            if typo_db.is_allowed_login():
                logger.info("Returning SUCEESS TypoToler")
                # entery by typo is allowed only after some initial number
                # of entry
                count_entry = typo_db.get_from_auxtdb(LoginCount, int)
                if count_entry <= NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED:
                    print("User has not logged in enough (only {}, required {})"
                          "to turn typo-tolerance on."\
                          .format(
                              count_entry, 
                              NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED
                          )
                      )
                    logger.info("User not entered because entry_count is {}"\
                                .format(count_entry))
                    return False
                return True
            else:
                print("Typotolerance is off!! {}".format(password))
                return False
    except ValueError as e:
        # probably  failre in decryption
        print("ValueError: {}".format(e))
    except UserTypoDB.CorruptedDB as e:
        print("Corrupted DB!")
        typo_db.set_status(2)
        # DB is corrupted, restart it
        # TODO
    except Exception as e:
        print("Unexpected error while on_wrong_password:\n{}\n"\
              .format(e))
    # finnaly block always run
    #finally:
    print("Nothing happened so returning false: {}".format(password))
    return False # previously inside "finally"
