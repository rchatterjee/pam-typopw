import logging
import os
import time
import json
import pwd
import struct
from base64 import urlsafe_b64encode, urlsafe_b64decode
from random import random
import dataset
from zxcvbn import password_strength
from pam_typtop.pw_pkcrypto2 import (
    encrypt, decrypt, generate_key_pair, compute_id,
    pkencrypt, pkdecrypt, harden_pw, encrypt_sk, verify,
    serialize_pk, deserialize_pk, serialize_sk, deserialize_sk,
    verify_pk_sk
)
from word2keypress import distance
from pam_typtop.config import *
from operator import itemgetter

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
    return encrypt(key, count_in_bytes)

def decode_decrypt_sym_count(key, ctx):
    """
    Receives the count ctx, decrypts it, decode it from base64
    and than from bytes to int
    """
    count_in_bytes = decrypt(key, ctx)
    # raise error if bigger? TODO
    return struct.unpack('<i',count_in_bytes)[0]

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

    def __init__(self, user, debug_mode=False): # TODO CHANGE to False
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

        self._sk, self._pk = None, None # always contains the
                                        # serialized versino of sk, pk
        self._idsalt, self._pw = None  # the global salt for the hmac, id

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
            logger.info("{}: N={}".format(typocacheT, self.N))
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

    def _hmac_id(self, typo):
        """
        Calculates the typo_id required for logging.
        @typo (string) : the typo
        @sk_dict (dict) : is a dictionar from t_h_id -> ECC secret_key,
        """
        assert self._idsalt
        return compute_id(bytes(typo.encode('utf-8')), self._idsalt)

    def _cache_entry(self, pw, edist, _id):
        sa, k, h = harden_pw(pw)
        sk_ctx = encrypt_sk(k, self._sk)
        return {
            'tid': self._hmac_id(pw),
            'sa': sa, 'h': h, 'sk_ctx': sk_ctx,
            'edit_dist': edist, 'id': _id
        }

    def is_allowed_login(self):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB(
                "is_allowed_login: Typotoler DB wasn't initiated yet!"
            )
        is_on = self._get_from_secdb(AllowedTypoLogin)
        assert is_on in ('True', 'False'), \
            'Corrupted data in {}: {}={}'.format(auxT, AllowedTypoLogin, is_on)
        return is_on == 'True'

    def init_typotoler(self, pw, N=CACHE_SIZE,
                       maxEditDist=EDIT_DIST_CUTOFF,
                       typoTolerOn=False):
        """Create the 'typotoler' database in user's home-directory.  Changes
        the DB permission to ensure its only readable by the user.
        Also, it intializes the required tables as well as the reuired
        variables, such as, the typocache size, the global salt etc.

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
        db[typocacheT].delete()
        db[waitlistT].delete()
        # doesn't delete log because it will also be used
        # whenever a password is changed
        self._sec_tab.delete() #

        # *************** Initializing Aux Data *************************
        install_id = urlsafe_b64encode(os.urandom(8))
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
        # 2. encrypt the global salt with the enc pk
        global_hmac_salt = os.urandom(16) # global salt
        pk, sk = generate_key_pair()  # ECC key pair
        self._sk = serialize_sk(sk)
        self._pk = pk
        pwid = compute_id(pw, global_hmac_salt)
        pw_ctx = pkencrypt(pk, json.dumps({
            'pw': pw,
            'idsalt': global_hmac_salt,
            'entropy': bytes(get_entropy_stat(pw))
        }))

        # note - we can't move any ctx to the 'read-only' pk_salt_t
        # because all ctx needs updating everytime a new typo enters Typocache
        self._sec_tab.insert_many([
            dict(desc=ORIG_PW_ID, data=str(pwid)),
            dict(desc=ORIG_PW_CTX, data=pw_ctx),
            dict(desc=ORIG_PW_ENC_PK, data=serialize_pk(pk)),
            dict(desc=EditCutoff, data=str(maxEditDist)),
            dict(desc=REL_ENT_BIT_DEC_ALLOWED, data=str(REL_ENT_CUTOFF)),
            dict(desc=LOWEST_ENT_BIT_ALLOWED, data=str(LOWER_ENT_CUTOFF)),
            dict(desc=CacheSize, data=str(N)),
            dict(desc=AllowedTypoLogin, data=str(typoTolerOn)),
            dict(desc=AllowUpload, data='True')
        ])
        self._sec_tab.create_index(['desc'])
        self.set_status('0') #sets status to init

        # 3.
        # Filling the Typocache with garbage
        logger.debug("Filling Typocache with garbage")
        f_list = [-random.randint(4294967294) for _ in xrange(self.N+1)]
        f_list[0] = 4294967295
        garbage_list = [self._cache_entry(pw, 0, 0)] + \
                       [self._cache_entry(
                           urlsafe_b64encode(os.urandom(32)), -1, i+1
                       ) for i in range(self.N)]
        self._db[typocacheT].insert_many(garbage_list)
        self._db[auxT].insert({
            'desc': 'flist', 
            'data': pkencrypt(self._pk, json.dumps(f_list))
        })
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
        # 1. derive public_key from the original password
        # 2. encrypt the global salt with the enc pk
        global_hmac_salt = os.urandom(16) # global salt
        pk, sk = generate_key_pair()  # ECC key pair
        self._sk = sk
        self._pk = pk
        pwid = compute_id(newPw, global_hmac_salt)
        db = self._db
        pw_ctx = pkencrypt(pk, json.dumps({
            'pw': newPw,
            'idsalt': global_hmac_salt,
            'pwent': bytes(get_entropy_stat(pw))
        }))
        for k, v in [(ORIG_PW_ID, str(pwid)),
                     (ORIG_PW_CTX, pw_ctx),
                     (ORIG_PW_ENC_PK, serialize_pk(pk))]:
            self._sec_tab.update(dict(desc=k, data=v), ['desc'])

        # 3 sending logs and deleting tables:
        logger.debug('Sending logs')
        self.update_last_log_sent_time(get_time(), True)

        logger.debug("Deleting tables")
        db[typocacheT].delete()
        db[waitlistT].delete()
        db[logT].delete()

        # Filling the Typocache with garbage
        logger.debug("Filling Typocache with garbage")
        f_list = [-random.randint(4294967294) for _ in xrange(self.N+1)]
        f_list[0] = 4294967295
        garbage_list = [self._cache_entry(newPw, 0)] + \
                       [self._cache_entry(
                           urlsafe_b64encode(os.urandom(32)),
                           -1
                       ) for _ in range(CACHE_SIZE)]
        self._db[typocacheT].insert_many(garbage_list)
        self._db[auxT].insert({
            'desc': 'flist', 
            'data': pkencrypt(self._pk, json.dumps(f_list))
        })
        self.set_status('0') #sets status to init
        logger.info("RE-Initialization Complete")

    def decrypt_pw_ctx(self, sk):
        # returns pw, idsalt, entropy
        # ORIG_PW_CTX contains: pw, idsalt, and entropy
        # TODO: Catch exceptions
        pw_info = pkdecrypt(sk, find_one(self._sec_tab, ORIG_PW_CTX))
        self._sk = sk
        self._pw = pw_info['pw']
        self._idsalt = pw_info['idsalt']
        self._pwent = pw_info['entropy']
        return self._pw

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

    def fetch_from_cache(self, typo, increaseCount=True, updateLog=True):
        '''Returns possible sk_dict, and whether the typo found in the cache
        By default:
            - increase the typo count
            - write the relevant log

        we removed the typo_id from the typocache for security reasons so it (as
        well as the difference in entropy) needs to be calculated every time -
        only if it is actually found

        @typo (string) : the given password typo
        @increaseCount (bool) : whether to update the typo's count if found
        @updateLog (bool) : whether to insert an update to the log

        '''
        logger.debug("Searching for typo in {}".format(typocacheT))
        # getting the pw's verify pk
        sgn_pk = self._get_from_secdb(ORIG_PW_SGN_PK)
        logger.debug("found signing key:{}".format(sgn_pk))

        cacheT = self._db[typocacheT]
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
                    typocacheT, sgn, t_h_id)
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
                "Typo found in {} (t_h_id={!r})".format(typocacheT, t_h_id)
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

        logger.debug("Typo wasn't found in {}".format(typocacheT))
        return {}, False

    def update_log(self, typo, other_info={}):
        """Updates the log with information about typo. Remember, if sk_dict is
        not provided it will insert @typo as typo_id and 0 as relative_entropy.
        Note the default values used in other_info, which is basically what
        is expected for the original password.
        """
        # Only log columns:
        log_columns = {'tid', 'time', 'edit_dist', 'rel_entropy', 'ts'
                       'istop5fixable', 'in_cache', 'allowed_login'}
        assert self._global_salt
        other_info['tid'] = compute_id(typo, self._global_salt)
        for col in log_columns:
            if col not in other_info:
                other_info[c] = -1

        other_info['ts'] = get_time()

        for col in other_info:
            if col not in log_columns:
                del other_info[col]

        if 'id' in other_info:
            del other_info['id']

        self._db[logT].insert(other_info)

    def log_orig_pw_use(self):
        ts = get_time()
        pw_id = self._get_from_secdb(ORIG_PW_ID, int)
        self.update_log(pw_id)

    def log_message(self, msg):
        ts = get_time()
        self._db[logT].insert(dict(t_id=msg, timestamp=ts))

    def _add_typo_to_waitlist(self, typo):
        """
        Adds the typo to the waitlist.
        saves the timestamp as well (for logging reasons)
        computes an hash for the typo (+sa)
        encryptes everything in a json format
        enc(json(dict(...)))
        dictionary keys: typo_hs, typo_pk, typo_pk_salt, timestamp, typo

        @typo (string) : the user's passwrod typo
        """
        logger.debug("Adding a new typo to waitlist")
        sa, k, h = harden_pw(typo)
        ent = get_entropy_stat(typo)
        ts = get_time()
        row = json.dumps((typo, sa, k, h, ent, ts))
        pk = self.get_pk()
        self._db[waitlistT].insert(dict(ctx=pkencrypt(pk, bytes(row))))
        logger.debug("Typo encrpted")

    def _decrypt_filter_waitlist(self, sk, orig_pw):
        '''
        Returns a list of the typos in waitlist, unsorted,
        Key = typo (string)
        Value = (typo, t_count, ts_list, typo_hs, t_pk, t_pk_salt)
        '''
        new_typo_dic = {}
        ignore = set()
        for line in self._db[waitlistT]:
            row = json.loads(pkdecrypt(sk, line['ctx']))
            typo, sa, k, h, ent, ts = row
            if typo in ignore: continue
            # TODO: Insert into the log, these are in waitlist, cache miss
            self.update_log(typo, ent, cache_hit=0)
            try:
                new_typo_dic[typo][-1].append(ts) # appending ts to ts_list
            except KeyError:
                if not self.validate(typo, orig_pw):
                    ignore.add(typo)
                new_typo_dic[typo] = (sa, k, h, [ts])
        logger.info("Waitlist decrypted successfully")
        return sorted(
            new_typo_dic.items(), key=lambda a: len(a[1][-1]), reverse=True
        )

    def get_table_size(self, tableName):
        return self._db[tableName].count()

    def get_typo_cache_size(self):
        return self.get_table_size(typocacheT)

    def get_orig_pw(self, sk):
        """
        Returns pw, pw's entropy (in bits)
        Mainly used after the user submitted an APPROVED typo,
        and now we need to original pw to calc edit_dist
        and the difference in entropy
        """
        if not self._pw or not self._pwent:
            self.decrypt_pw_ctx(sk)
        return self._pw, self._pwent

    def get_pk(self):
        """Returns the public key"""
        if not self._pk:
            self._pk = self._get_from_secdb(ORIG_PW_ENC_PK)
        return deserialize_pk(self._pk)

    def get_global_salt(self, sk):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        assert False
        if not self._global_salt:
            try:
                salt_ctx = self.get_from_auxtdb(GLOBAL_SALT_CTX)
                self._global_salt = pkdecrypt(sk,  salt_ctx)
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

    def check(self, pw):
        logger.info("Original password had been entered by user")
        pk = self.get_pk()   # cannot be tampered
        sk = None
        for i, row in enumerate(self._db[typocacheT]):
            sa, h, sk_ctx = row['sa'], row['h'], row['sk_ctx']
            k = verify(pw, sa, h)
            if not k: continue  # not a match
            sk, f = json.loads(decrypt(k, sk_ctx))
            if verify_pk_sk(pk, sk):  #  Somehow the hash matched !!
                if i>0:  # Update the entry in the cache
                    row['sk_ctx'] = encrypt(k, json.dumps((sk, f+1)))
                    self._db[typocacheT].update(row, ['tid'])
                break
            else:
                sk = None
        # We have 'sk' now
        logger.debug("Deriving secret key of the password")
        if not sk:
            self.add_typo_to_waitlist(pw)
            return False

        # get original password 
        # Very important function, TODO: rename
        orig_pw = self.decrypt_pw_ctx(sk)
        assert self.validate(orig_pw, pw)
        self._sk = sk
        self._update_typo_cache_by_waitlist(sk, self._pw)
        return True

    def _get_from_secdb(self, key, apply_type=str):
        return find_one(self._sec_tab, key, apply_type)

    def get_from_auxtdb(self, key, apply_type=str):
        return find_one(self._db[auxT], key, apply_type)

    def validate(self, orig_pw, typo):
        editDist = distance(str(orig_pw), str(typo))
        typo_ent = get_entropy_stat(typo)
        rel_entropy = typo_ent - self._pwent
        
        rel_bound = self._get_from_secdb(REL_ENT_BIT_DEC_ALLOWED, int)
        strict_bound = self._get_from_secdb(LOWEST_ENT_BIT_ALLOWED, int)
        edist_bound = self._get_from_secdb(EditCutoff, int)
        
        notMuchWeaker = (rel_entropy >= rel_bound)
        notTooWeak = (typo_ent >= strict_bound)
        closeEdit = (editDist <= edist_bound)
        return (notTooWeak and notMuchWeaker and closeEdit)

    def _update_typo_cache_by_waitlist(self, sk, orig_pw):
        """
        Updates the hash cache according to waitlist.
        It also updates the log accordingly (if updateLog is set)
        and clears waitlist
        sk: the secrete key found in previous function
        orig_pw: retrieved original password, 
        """
        logger.info("Updating {} by {}".format(typocacheT, waitlistT))
        good_typo_dict = self._decrypt_filter_waitlist(sk, orig_pw)
        flist_ctx = self.get_from_auxtdb('flist')
        if not self._sk:
            self._sk = serialize_sk(sk)
        flist = json.loads(pkdecrypt(sk, flist_ctx))
        mini, minf = min(enumerate(flist), key=itemgetter(1))
        cache_t = self._db[typocacheT]
        for typo, typo_info in good_typo_dict.items():
            sa, k, h, ts = typo_info
            f = len(ts)
            if self.cache_insert_policy(minf, f):
                sk_ctx = encrypt_sk(k, self._sk)
                cache_line = {
                    'tid': self._hmac_id(typo),
                    'sa': sa, 'h': h, 'sk_ctx': sk_ctx,
                    'edit_dist': distance(str(typo), str(orig_pw)), 
                    'id': mini
                }
                cache_t.update(cache_line, ['id'])
                flist[mini] = minf + f
                mini, minf = min(enumerate(flist), key=itemgetter(1))
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
            raise UserTypoDB.CorruptedDB(
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
            typo_db.update_typo_cache_by_waitlist(sk_dict, typo=password)
            if typo_db.is_allowed_login():
                logger.info("Returning SUCEESS TypoToler")
                # entery by typo is allowed only after some initial number
                # of entry
                count_entry = typo_db.get_from_auxtdb(LoginCount, int)
                if count_entry <= NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED:
                    logger.error("User has not logged in enough (only {}, required {})"
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
                logger.error("Typotolerance is off!! {}".format(password))
                return False
    except ValueError as e:
        # probably  failre in decryption
        logger.error("ValueError: {}".format(e))
    except UserTypoDB.CorruptedDB as e:
        logger.error("Corrupted DB!")
        typo_db.set_status(2)
        # DB is corrupted, restart it
        # TODO
    except Exception as e:
        logger.error("Unexpected error while on_wrong_password:\n{}\n"\
              .format(e))
        print("TypToP is not initialized.\n $ sudo typtop --init")
    return False # previously inside "finally"
