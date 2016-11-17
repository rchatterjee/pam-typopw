import logging
import os
import time
import json
import pwd
from base64 import urlsafe_b64encode, urlsafe_b64decode
import random
import dataset
from zxcvbn import password_strength
from pam_typtop.pw_pkcrypto2 import (
    encrypt, decrypt, generate_key_pair, compute_id,
    pkencrypt, pkdecrypt, harden_pw, verify,
    serialize_pk, deserialize_pk, serialize_sk,
    verify_pk_sk, SALT_LENGTH
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
def setup_logger(logfile_path, log_level, user):
    logger.setLevel(log_level)
    if not logger.handlers:  # if it doesn't have an handler yet:
        handler = logging.FileHandler(logfile_path)
        formatter = logging.Formatter(
            '%(asctime)s:%(levelname)s:<{}>:[%(filename)s:%(lineno)s'\
            '(%(funcName)s)>> %(message)s'.format(user)
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

def get_time():
    """
    Returns the timestamp in a string, in a consistent format
    which works in linux and can be stored in the DB
    (unlike datetime.datetime, for example)
    """
    return str(time.time())

_entropy_cache = {}
def get_entropy_stat(typo):
    global _entropy_cache
    if typo not in _entropy_cache:
        _entropy_cache[typo] = password_strength(typo)['entropy']
    return _entropy_cache[typo]

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
        # homedir = pwd.getpwnam(self._user).pw_dir
        typo_dir = os.path.join(SEC_DB_PATH, user)
        if not os.path.exists(typo_dir): # creating dir only if it doesn't exist
            # this directory needs root permission, and should be created as
            # part of the installation process
            try:
                os.makedirs(typo_dir)
            except OSError as error:
                print("Trying to create: {}, but seems like the database "
                      "is not initialized.".format(typo_dir))
                raise UserTypoDB.NoneInitiatedDB(error)

        self._db_path = os.path.join(typo_dir, DB_NAME + '.db')
        self._log_path = os.path.join(LOG_DIR, DB_NAME + '.log')
        self._db = dataset.connect('sqlite:///{}'.format(self._db_path))
        self._aux_tab = self._db.get_table(
            auxT,
            primary_id='desc',
            primary_type='String(100)'
        )
        # always contains the serialized versino of sk, pk
        self._sk, self._pk = None, None 
        # the global salt for the hmac-id only will be available if
        # correct pw is provided.
        self._hmac_salt, self._pw, self._pwent = None, None, None
        self._aux_tab_cache = {}  # For caching results from auxtab
        # setting the logger object
        log_level = logging.DEBUG if debug_mode else logging.INFO
        setup_logger(self._log_path, log_level, user)
        dataLine_N = self.get_from_auxtdb(CacheSize, int)
        if dataLine_N:
            self.N = dataLine_N
            logger.info("{}: N={}".format(typocacheT, self.N))
        else:
            self.N = CACHE_SIZE
        self.isON = self.get_from_auxtdb(AllowedTypoLogin, bool)
        logger.info("typoToler is ON? {}".format(self.isON))

    def getdb(self):
        return self._db

    def get_db_path(self):
        return self._db_path

    @staticmethod
    def get_logging_path(username):
        homedir = pwd.getpwnam(username).pw_dir
        return "{}/{}.log".format(homedir, DB_NAME)

    def is_typotoler_init(self):
        """
        Returns whether the typotoler has been set (might be installed
        but not active)
        """
        installid = self.get_from_auxtdb(InstallationID)
        allowed_login = self.get_from_auxtdb(ORIG_PW_ENC_PK)

        if ((not allowed_login) != (not installid)):
            # if globSalt and pw aren't in the same initialization state
            if not allowed_login:
                stub = 'global salt is missing'
            else:
                stub = 'pw is missing'
            logger.critical('DB is corrupted: {}'.format(stub))
            raise UserTypoDB.CorruptedDB(
                "{} is corrupted!  secdb={}  auxdb={}"\
                .format(auxT, allowed_login, installid)
            )
        # if typoToler is initiates, it has both the normal AuxT and
        # the secure table
        return (allowed_login and installid)

    def _hmac_id(self, typo):
        """
        Calculates the typo_id required for logging.
        @typo (string) : the typo
        @sk_dict (dict) : is a dictionar from t_h_id -> ECC secret_key,
        """
        assert self._hmac_salt
        return compute_id(self._hmac_salt, bytes(typo))

    def _cache_entry(self, pw, edist, _id):
        sa, k, h = harden_pw(pw)
        sk_ctx = encrypt(k, self._sk)  # assumes self._sk is serialized
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
        is_on = self.get_from_auxtdb(AllowedTypoLogin, bool)
        assert is_on in (True, False), \
            'Corrupted data in {}: {}={} ({})'.format(
                auxT, AllowedTypoLogin, is_on, type(is_on)
            )
        return is_on

    def allow_login(self, allow=True):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB(
                "allow_login: Typotoler DB wasn't initiated yet!"
            )
        assert allow in (True, False, 0, 1), "Expects a boolean"
        allow = True if allow else False
        self._aux_tab.update(
            dict(desc=AllowedTypoLogin, data=str(allow)),
            ['desc']
        )
        self._aux_tab_cache[AllowedTypoLogin] = allow
        self.isON = allow
        state = "ON" if allow else "OFF"
        logger.info("typoToler set to {}".format(state))

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
        # os.chmod(db_path, 0640)  # RW only for owner

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

        # *************** Initializing Aux Data *************************
        self._aux_tab = self._db.get_table(
            auxT, primary_id='desc', primary_type='String(100)'
        )
        self._aux_tab_cache = {}
        install_id = urlsafe_b64encode(os.urandom(8))
        install_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        last_sent_time = get_time()

        # *************** add org password, its' pks && global salt: ********
        # 1. derive public_key from the original password
        # 2. encrypt the global salt with the enc pk
        global_hmac_salt = os.urandom(SALT_LENGTH) # global salt
        self._hmac_salt = global_hmac_salt
        pk, sk = generate_key_pair()  # ECC key pair
        self._sk = serialize_sk(sk)
        self._pk = pk
        self._pw = pw
        pwid = compute_id(global_hmac_salt, pw)
        pw_ctx = pkencrypt(pk, json.dumps({
            'pw': self._pw,
            'hmac_salt': urlsafe_b64encode(global_hmac_salt),
            'entropy': bytes(get_entropy_stat(pw))
        }))

        logger.info("Initializing the auxiliary data base ({})".format(auxT))
        db[auxT].insert_many([
            dict(desc=InstallationID, data=install_id),
            dict(desc=InstallDate, data=install_time),
            dict(desc=LastSent, data=str(last_sent_time)),
            dict(desc=SendEvery, data=str(UPDATE_GAPS)),
            dict(desc=SysStatus, data=str(0)),
            dict(desc=LoginCount, data=str(0)),
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
        self.N = N
        self.isON = typoTolerOn
        self._aux_tab.create_index(['desc'])
        self._aux_tab_cache = {}
        self.set_status('0') #sets status to init
        # 3.
        self._fill_cache_w_garbage()
        # Filling the Typocache with garbage
        logger.debug("Initialization Complete")

    def _fill_cache_w_garbage(self):
        logger.debug("Filling Typocache with garbage")
        f_list = [-random.randint(0, 4294967294) for _ in xrange(self.N+1)]
        f_list[0] = 4294967295
        garbage_list = [self._cache_entry(self._pw, 0, 0)] + \
                       [self._cache_entry(
                           urlsafe_b64encode(os.urandom(4)), 
                           random.randint(0,1), i+1
                       ) for i in range(self.N)]
        self._db[typocacheT].insert_many(garbage_list)
        ctx = bytes(pkencrypt(self._pk, json.dumps(f_list)))
        self._db[auxT].upsert({
            'desc': FreqList, 
            'data': ctx
        }, ['desc'])
        self._aux_tab_cache[FreqList] = ctx
        self._db.commit()

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
        self._hmac_salt = global_hmac_salt
        pk, sk = generate_key_pair()  # ECC key pair
        self._pk, self._sk = pk, serialize_sk(sk)
        self._pw = newPw
        pwid = compute_id(global_hmac_salt, newPw)
        db = self._db
        pw_ctx = pkencrypt(pk, json.dumps({
            'pw': newPw,
            'hmac_salt': urlsafe_b64encode(global_hmac_salt),
            'entropy': bytes(get_entropy_stat(newPw))
        }))
        for k, v in [(ORIG_PW_ID, str(pwid)),
                     (ORIG_PW_CTX, pw_ctx),
                     (ORIG_PW_ENC_PK, serialize_pk(pk))]:
            self._aux_tab.update(dict(desc=k, data=v), ['desc'])
            self._aux_tab_cache[k] = v
        # 3 sending logs and deleting tables:
        logger.debug('Sending logs')
        self.update_last_log_sent_time(get_time(), True)

        logger.debug("Deleting tables")
        db[typocacheT].delete()
        db[waitlistT].delete()
        db[logT].delete()
        db.commit()
        # Filling the Typocache with garbage
        self._fill_cache_w_garbage()
        self.set_status('0') #sets status to init
        logger.info("RE-Initialization Complete")

    def decrypt_pw_ctx(self, sk):
        # returns pw, hmac_salt, entropy
        # ORIG_PW_CTX contains: pw, hmac_salt, and entropy
        # TODO: Catch exceptions
        pw_info = json.loads(pkdecrypt(sk, self.get_from_auxtdb(ORIG_PW_CTX)))
        self._sk = sk
        self._pw = pw_info['pw']
        self._hmac_salt = urlsafe_b64decode(bytes(pw_info['hmac_salt']))
        self._pwent = float(pw_info['entropy'])
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
        upload_status = self.get_from_auxtdb(AllowUpload)
        if not upload_status:
            raise UserTypoDB.CorruptedDB(
                "Missing {} in {}".format(AllowUpload, auxT)
            )
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
        if allow in (0, 1):
            allow = bool(allow)
        assert isinstance(allow, bool)
        self._aux_tab.upsert(
            dict(desc=AllowUpload, data=str(allow)),
            ['desc']
        )
        self._aux_tab_cache[AllowUpload] = allow
        self.isON = allow

    def is_allowed_upload(self):
        send_stat_row = self.get_from_auxtdb(AllowUpload, bool)
        return send_stat_row

    def update_log(self, typo, incache, ts=None):
        """Updates the log with information about typo. Remember, if sk_dict is
        not provided it will insert @typo as typo_id and 0 as relative_entropy.
        Note the default values used in other_info, which is basically what
        is expected for the original password.
        """
        assert self._pw and self._hmac_salt
        # Only log columns:
        log_columns = {'tid', 'edit_dist', 'rel_entropy', 'ts',
                       'istop5fixable', 'in_cache'}
        log_info = {
            'tid': compute_id(self._hmac_salt, typo),
            'edit_dist': distance(str(self._pw), str(typo)),
            'rel_entropy': self._pwent - get_entropy_stat(typo),
            'ts': ts if ts else get_time(),
            'istop5fixable': is_in_top5_fixes(self._pw, typo),
            'in_cache': incache
        }
        self._db[logT].insert(log_info)

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
        ts = get_time()
        row = json.dumps((typo, sa, urlsafe_b64encode(k), h, ts))
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
            typo, sa, k, h, ts = row
            self.update_log(typo, incache=False, ts=ts)
            if typo in ignore: continue
            # TODO: Insert into the log, these are in waitlist, cache miss
            try:
                new_typo_dic[typo][-1].append(ts) # appending ts to ts_list
            except KeyError:
                if not self.validate(orig_pw, typo):
                    ignore.add(typo)
                else:
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
            self._pk = self.get_from_auxtdb(ORIG_PW_ENC_PK)
        return deserialize_pk(self._pk)

    def get_hmac_salt(self, sk):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        assert False
        if not self._hmac_salt:
            try:
                salt_ctx = self.get_from_auxtdb(HMAC_SALT_CTX)
                self._hmac_salt = pkdecrypt(sk,  salt_ctx)
            except ValueError as e:
                logging.debug(
                    "Sorry wrong id-sk pair ({}). Couldn't decrypt the salt"\
                    .format(sk)
                )
        return self._hmac_salt

    # TODO FUTURE
    @staticmethod
    def cache_insert_policy(old_t_c, new_t_c):
        if old_t_c < 0: # for garbage rows in cache
            return True
        d = old_t_c + new_t_c
        rnd = random.randint(0, d)
        return rnd < new_t_c 

    def clear_waitlist(self):
        self._db[waitlistT].delete()
        logger.info("{} had been deleted".format(waitlistT))

    def check_login_count(self, update=False):
        """Keeps track of how many times the user has successfully logged in."""
        count_entry = self.get_from_auxtdb(LoginCount, int) + 1
        if update:
            self._db[auxT].update(
                dict(desc=LoginCount, data=str(count_entry)),
                ['desc']
            )
        return count_entry > NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED

    def check(self, pw):
        logger.info("Original password had been entered by user")
        pk = self.get_pk()   # cannot be tampered
        sk = None
        is_typo_login = False
        for i, row in enumerate(self._db[typocacheT]):
            sa, h, sk_ctx = row['sa'], row['h'], row['sk_ctx']
            k = verify(pw, sa, h)
            if not k: continue  # not a match
            sk = decrypt(k, sk_ctx)
            if verify_pk_sk(pk, sk):  #  Somehow the hash matched !!
                flist_ctx = self.get_from_auxtdb(FreqList)
                if not self._sk:
                    self._sk = sk
                f_list = json.loads(pkdecrypt(sk, flist_ctx))
                if i>0:  # Update the entry in the cache
                    f_list[row['id']] += 1
                    self._db[typocacheT].update(row, ['tid'])
                    is_typo_login = (self.check_login_count(update=False) and
                                     self.is_allowed_login())
                else:  # Correct password, no more check, just accept.
                    self.check_login_count(update=True)
                break
            else:
                sk = None
        if not sk:
            self._add_typo_to_waitlist(pw)
            return 0
        logger.debug("Deriving secret key of the password")

        # We have sk now, get original password, and validate, to make
        # sure, that a valid typo is being processed. decrypt_pw_ctx
        # is a very important function, TODO: rename
        orig_pw = self.decrypt_pw_ctx(sk)
        self.update_log(pw, incache=True) # TODO: adequate parameter
        assert self.validate(orig_pw, pw) 
        self._update_typo_cache_by_waitlist(sk, self._pw)
        return 2 if is_typo_login else 1 

    def get_from_auxtdb(self, key, apply_type=str):
        if key not in self._aux_tab_cache:
            self._aux_tab_cache[key] = find_one(self._aux_tab, key, apply_type)
        return find_one(self._db[auxT], key, apply_type)

    def validate(self, orig_pw, typo):
        editDist = distance(str(orig_pw), str(typo))
        typo_ent = get_entropy_stat(typo)
        rel_entropy = typo_ent - self._pwent
        
        rel_bound = self.get_from_auxtdb(REL_ENT_BIT_DEC_ALLOWED, int)
        strict_bound = self.get_from_auxtdb(LOWEST_ENT_BIT_ALLOWED, int)
        edist_bound = self.get_from_auxtdb(EditCutoff, int)
        
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
        good_typo_list = self._decrypt_filter_waitlist(sk, orig_pw)
        flist_ctx = self.get_from_auxtdb(FreqList)
        if not self._sk:
            self._sk = serialize_sk(sk)
        f_list = json.loads(pkdecrypt(sk, flist_ctx))
        mini, minf = min(enumerate(f_list), key=itemgetter(1))
        cache_t = self._db[typocacheT]
        for typo, typo_info in good_typo_list:
            sa, k, h, ts = typo_info
            k = urlsafe_b64decode(bytes(k))
            f = len(ts)
            if UserTypoDB.cache_insert_policy(minf, f):
                sk_ctx = encrypt(k, self._sk)
                cache_line = {
                    'tid': self._hmac_id(typo),
                    'sa': sa, 'h': h, 'sk_ctx': sk_ctx,
                    'edit_dist': distance(str(typo), str(orig_pw)), 
                    'id': mini
                }
                cache_t.update(cache_line, ['id'])
                f_list[mini] = max(minf + 1, f)
                mini, minf = min(enumerate(f_list), key=itemgetter(1))
        self._db[auxT].update({
            'desc': FreqList, 
            'data': pkencrypt(self._pk, json.dumps(f_list))
        }, ['desc'])
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

STATUS_DICT = dict(
    active=0,
    password_changed=1,
    corrupted_db=2
)

def on_correct_password(typo_db, password):
    logger.info("sm_auth: it's the right password")
    # log the entry of the original pwd
    try:
        if not typo_db.is_typotoler_init():
            print("ERROR: (on_correct_pass) Typotoler DB wasn't initiated yet!")
            typo_db.init_typotoler(password)
            # the initialization is now part of the installation process
        sysStatVal = typo_db.get_from_auxtdb(SysStatus)
        if not sysStatVal: # if not found in table
            raise UserTypoDB.CorruptedDB(
                "ERROR: (on_correct_password) Typotoler DB is Corrupted."
            )
        if int(sysStatVal) == 1:  # pasword_changed
            raise KeyError
        if int(sysStatVal) == 2:  # corrupted_db
            raise UserTypoDB.CorruptedDB("")

        # if reached here - db should be initiated
        # updating the entry count
        ret = typo_db.check(password)    # also updates the log
        if ret == 0:  # correct password but db fails to see it
            typo_db.set_status(1)
        return True
    except UserTypoDB.CorruptedDB as e:
        logger.error("Corrupted DB!")
        typo_db.set_status(2)
        # DB is corrupted, needs restart
    except (ValueError, KeyError) as e:
        # most probably - an error of decryption as a result of pw change
        typo_db.set_status(1)
        logger.error("Key error raised. Probably a failure in decryption.")
        logger.exception("Exception in on_correct_password:")
    except Exception as e:
        logger.error(
            "Unexpected error while on_correct_password:\n{}\n"\
            .format(e)
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
        ret = typo_db.check(password)
        return ret==2
    except (ValueError, KeyError) as e:
        # probably  failre in decryption
        logger.exception("ValueError: {}".format(e))
    except UserTypoDB.CorruptedDB as e:
        # DB is corrupted, restart it
        logger.error("Corrupted DB!")
        typo_db.set_status(2)

    except Exception as e:
        logger.exception("Unexpected error while on_wrong_password:\n{}\n"\
              .format(e))
        print("TypToP is not initialized.\n $ sudo typtop --init")
    return False # previously inside "finally"
