#!/usr/bin/env python2.7

import os
import time
import json
import yaml
import sys
import pwd
import random
from zxcvbn import password_strength
from collections import defaultdict
from base64 import urlsafe_b64encode, urlsafe_b64decode
from word2keypress import distance
from operator import itemgetter

# Local libraries
from typtop.dbutils import (
    logger, setup_logger, is_user, get_machine_id, is_in_top5_fixes,
    change_db_ownership
)
from typtop.config import (
    DB_NAME, auxT, INSTALLATION_ID,
    INSTALLATION_DATE, LOG_LAST_SENTTIME, LOG_SENT_PERIOD,
    UPDATE_GAPS, SYSTEM_STATUS, SYSTEM_STATUS_NOT_INITIALIZED,
    LOGIN_COUNT, ALLOWED_TYPO_LOGIN, ALLOWED_UPLOAD, ENC_PK, INDEX_J,
    WAITLIST_SIZE, WARM_UP_CACHE, CACHE_SIZE, REAL_PW, HMAC_SALT,
    FREQ_COUNTS, HEADER_CTX, SYSTEM_STATUS_ALL_GOOD, LOWER_ENT_CUTOFF,
    EDIT_DIST_CUTOFF, WAIT_LIST, TYPO_CACHE, SEC_DB_PATH,
    NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN, REL_ENT_CUTOFF, TEST,
    SYSTEM_STATUS_PW_CHANGED, SYSTEM_STATUS_CORRUPTED_DB, LOG_DIR,
    logT, GROUP, warm_up_with
)
from typtop.pw_pkcrypto import (
    generate_key_pair, compute_id,
    pkencrypt, pkdecrypt, pwencrypt, pwdecrypt,
    serialize_pk, deserialize_pk, serialize_sk, deserialize_sk,
    verify_pk_sk, SALT_LENGTH
)

# GENERAL TODO:
# - improve computation speed. I have moved to json file, but
#   still slow.
#

_entropy_cache = {}


def get_logging_path(username):
    homedir = pwd.getpwnam(username).pw_dir
    return "{}/{}.log".format(homedir, DB_NAME)


def get_time():
    """
    Returns the timestamp in a string, in a consistent format
    which works in linux and can be stored in the DB
    (unlike datetime.datetime, for example)
    """
    return time.time()


def entropy(typo):
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

    def __init__(self, user, debug_mode=False):
        # type: (string, boolean) -> UserTypoDB
        assert is_user(user), "User {!r} does not exists".format(user)

        # Disable Typtop for root
        # assert pwd.getpwnam(user).pw_uid != 0,\
        #     "Currently Typtop is disabled for {} user.".format(user)

        self._user = user  # this is a real user.
        # homedir = pwd.getpwnam(self._user).pw_dir
        typo_dir = os.path.join(SEC_DB_PATH, user)
        self._db_path = os.path.join(typo_dir, DB_NAME + '.json')
        self._log_path = os.path.join(LOG_DIR, DB_NAME + '.log')
        # First thing first -- setting the logger object
        setup_logger(self._log_path, debug_mode, user)
        self.logger = logger  # just in case I need it
        logger.info("---UserTypoDB instantiated---")

        # creating dir only if it doesn't exist
        if not os.path.exists(typo_dir):
            try:
                os.makedirs(typo_dir)
                os.system(
                    "chgrp {1} {0} && chmod -R g+w {0} && chmod -R o-rw {0} {0}".format(typo_dir, GROUP)
                )
            except OSError as error:
                logger.error("Trying to create: {}, but seems like the database"
                             " is not initialized.".format(typo_dir))
                raise UserTypoDB.NoneInitiatedDB(error)

        if not os.path.exists(self._db_path):
            with open(self._db_path, 'w') as dbf:
                json.dump({}, dbf)
            # cmd = 'chown root:{1} {0} && chmod o-rw {0};'.format(self._db_path, GROUP)
            change_db_ownership(self._db_path)

        try:
            self._db = json.load(open(self._db_path, 'r'))
        except (ValueError, IOError) as e:
            self._db = {}

        if auxT in self._db:
            self._aux_tab = self._db[auxT]
        else:
            self._aux_tab = self._db[auxT] = {}

        # always contains the serialized versin of sk, pk
        self._sk, self._pk = None, None
        # the global salt for the hmac-id only will be available if
        # correct pw is provided.
        self._hmac_salt, self._pw, self._pwent = None, None, None

    def __del__(self):
        tmp_f = self._db_path + '.tmp'
        with open(tmp_f, 'wb') as f:
            json.dump(self._db, f, indent=2)
            f.flush(); os.fsync(f.fileno())
        os.rename(tmp_f, self._db_path)
        change_db_ownership(self._db_path)
        logger.info("---UserTypoDB deleted---")

    def init_typtop(self, pw, allow_typo_login=True):
        """Create the 'typtop' database in user's home-directory.  Changes

        Also, it initializes the required tables as well as the reuired
        variables, such as, the typo-cache size, the global salt etc.

        """
        logger.info("Initiating typtop db with {}".format(
            dict(allow_typo_login=allow_typo_login)
        ))
        change_db_ownership(self._db_path)

        # db[auxT].delete()         # make sure there's no old unrelevent data
        # doesn't delete log because it will also be used
        # whenever a password is changed

        # *************** Initializing Aux Data *************************
        # *************** add org password, its' pks && global salt: ********
        # 1. derive public_key from the original password
        # 2. encrypt the global salt with the enc pk
        install_id = get_machine_id()
        install_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        last_sent_time = get_time()
        self._hmac_salt = os.urandom(SALT_LENGTH) # global salt
        self._pk, self._sk = generate_key_pair()  # ECC key pair
        self._sk = serialize_sk(self._sk)
        self._pw = pw
        self._aux_tab.update({
            INSTALLATION_ID: install_id,
            INSTALLATION_DATE: install_time,
            LOG_LAST_SENTTIME: last_sent_time,
            LOG_SENT_PERIOD: UPDATE_GAPS,
            SYSTEM_STATUS: SYSTEM_STATUS_NOT_INITIALIZED,
            LOGIN_COUNT: 0,
            ALLOWED_TYPO_LOGIN: allow_typo_login,
            ALLOWED_UPLOAD: True,
            ENC_PK: serialize_pk(self._pk),
            INDEX_J: random.randint(0, WAITLIST_SIZE-1),
        })

        # Just get the ids of all possible typo candidates for warming
        # up the cache.
        perm_index = self._fill_cache_w_garbage()
        if WARM_UP_CACHE:
            freq_counts = range(CACHE_SIZE, 0, -1)
            for i in range(CACHE_SIZE):
                freq_counts[perm_index[i]] = freq_counts[i]
        else:
            freq_counts = [0 for _ in range(CACHE_SIZE)]
        header_ctx = pkencrypt(self._pk, json.dumps({
            REAL_PW: self._pw,
            HMAC_SALT: urlsafe_b64encode(self._hmac_salt),
            FREQ_COUNTS: freq_counts
        }))

        logger.info("Initializing the auxiliary data base ({})".format(auxT))
        self._aux_tab[HEADER_CTX] = header_ctx

        # self._aux_tab.create_index(['desc'])
        self.set_status(SYSTEM_STATUS_ALL_GOOD)
        # 3. Filling the Typocache with garbage
        self._fill_waitlist_w_garbage()
        logger.debug("Initialization Complete")
        isON = self.get_from_auxtdb(ALLOWED_TYPO_LOGIN)   # isON: boolean
        logger.info("typtop is ON? {}".format(isON))

    def reinit_typtop(self, newPw):
        """
        Re-initiate the DB after a pw change.
        Most peripherial system settings don't change, including installID
        generates a new hmac salt,
        and encrypts the new pw, pw_ent, and the hmac salt
        """
        if not self.is_typtop_init():
            self.init_typtop(newPw)
        # Mostly a simple copy-paste of steps 1 to 2.5
        logger.info("Re-intializing after a pw change")
        # 1. derive public_key from the original password
        # 2. encrypt the global salt with the enc pk
        self._hmac_salt = os.urandom(16) # global salt
        pk, sk = generate_key_pair()  # ECC key pair
        self._pk, self._sk = pk, serialize_sk(sk)
        self._pw = newPw
        perm_index = self._fill_cache_w_garbage()
        if WARM_UP_CACHE:
            freq_counts = range(CACHE_SIZE, 0, -1)
            for i, f in enumerate(range(CACHE_SIZE)):
                freq_counts[perm_index[i]] = freq_counts[i]
        else:
            freq_counts = [0 for _ in range(CACHE_SIZE)]

        header_ctx = pkencrypt(self._pk, json.dumps({
            REAL_PW: self._pw,
            HMAC_SALT: urlsafe_b64encode(self._hmac_salt),
            FREQ_COUNTS: freq_counts
        }))
        self.set_in_auxtdb(HEADER_CTX, header_ctx)
        self.set_in_auxtdb(ENC_PK, serialize_pk(self._pk))
        # 3 sending logs and deleting tables:
        logger.debug("Sending logs, deleting tables")

        # 4. Filling the Typocache with garbage
        self._fill_waitlist_w_garbage()
        self.set_status(SYSTEM_STATUS_ALL_GOOD)
        logger.info("RE-Initialization Complete")

    def is_typtop_init(self):
        """
        Returns whether the typtop has been set (might be installed
        but not active)
        """
        if not os.path.exists(self._db_path):
            return False
        if self.get_from_auxtdb(HEADER_CTX):
            return True
        else:
            return False

    def getdb(self, tabname):
        if tabname in self._db:
            return self._db[tabname]
        else:
            self._db[tabname] = []
            return self._db[tabname]

    def get_db_path(self):
        return self._db_path

    def assert_initialized(self):
        if not self.is_typtop_init():
            raise UserTypoDB.NoneInitiatedDB(
                "Typtop DB wasn't initiated yet!"
            )

    def is_allowed(self, what):
        self.assert_initialized()
        isON = self.get_from_auxtdb(what)
        assert isON in (True, False), \
            'Corrupted data in {}: {}={} ({})'.format(
                auxT, what, isON, type(isON)
            )
        return isON

    def allow(self, what, how):
        self.assert_initialized()
        assert how in (True, False, 0, 1), "Expects a boolean"
        how = True if how else False
        self.set_in_auxtdb(what, how)
        state = "ON" if how else "OFF"
        logger.info("typtop::{} set to {}".format(what, state))

    def allow_upload(self, allow):
        self.allow(ALLOWED_UPLOAD, allow)

    def allow_login(self, allow=True):
        self.allow(ALLOWED_TYPO_LOGIN, allow)

    def is_allowed_login(self):
        return self.is_allowed(ALLOWED_TYPO_LOGIN)

    def is_allowed_upload(self):
        return self.is_allowed(ALLOWED_UPLOAD)

    def is_real_pw(self, pw):
        return self._pw == pw

    def _fill_waitlist_w_garbage(self):
        ts = get_time()
        install_id = self.get_installation_id()

        def randomstring(k):
            return urlsafe_b64encode(os.urandom(k))

        waitlist = [
            pkencrypt(
                self._pk,
                json.dumps([install_id+randomstring(16), ts])
            )
            for _ in range(WAITLIST_SIZE)
        ]
        self.set_in_auxtdb(WAIT_LIST, waitlist)

    def _fill_cache_w_garbage(self):
        logger.debug("Filling Typocache with garbage")
        perm_index = range(CACHE_SIZE)
        random.shuffle(perm_index)
        pw = self._pw
        popular_typos = [os.urandom(16) for _ in range(CACHE_SIZE)]
        self._pwent = entropy(self._pw)

        # if WARM_UP_CACHE: # No need to check, assumes always WARM_UP
        i = 0
        for tpw in warm_up_with(pw):
            if WARM_UP_CACHE and i < CACHE_SIZE and pw != tpw and tpw not in popular_typos:
                self.insert_log(typo=tpw, in_cache=True, ts=-1)
                popular_typos[perm_index[i]] = tpw
                i += 1
            elif pw != tpw:
                self.insert_log(typo=tpw, in_cache=False, ts=-1)

        popular_typos = [pw] + popular_typos
        garbage_list = [
            pwencrypt(tpw, self._sk) for tpw in popular_typos
        ]
        self.set_in_auxtdb(TYPO_CACHE, garbage_list)
        return perm_index

    def get_installation_id(self):
        self.assert_initialized()
        return self.get_from_auxtdb(INSTALLATION_ID)

    def get_last_unsent_logs_iter(self, force=False):
        """
        Check what was the last time the log has been sent,
        And returns whether the log should be sent
        """
        logger.debug("Getting last unsent logs")
        if not self.is_typtop_init():
            logger.debug("Could not send. Typtop not initiated")
            return False, iter([])
        if not self.is_allowed_upload():
            logger.info("Not sending logs because send status set to False")
            return False, iter([])
        last_sending = self.get_from_auxtdb(LOG_LAST_SENTTIME)  # , float)
        update_gap = self.get_from_auxtdb(LOG_SENT_PERIOD)  # , float)
        time_now = time.time()
        passed_enough_time = ((time_now - last_sending) >= update_gap)
        if not force and not passed_enough_time:
            logger.debug("Not enough time has passed ({}) to send new logs."
                         .format(str(last_sending)))
            return False, iter([])
        log_t = self._db[logT]
        try:
            new_logs = iter(log_t)  # .find(log_t.table.columns.ts >= last_sending)
            logger.info("Prepared new logs to be sent, from {} to {}".format(
                str(last_sending), str(time_now))
            )
            return True, new_logs
        except AttributeError:
            return False, iter([])

    def update_last_log_sent_time(self, sent_time=0, delete_old_logs=True):
        logger.debug("updating log sent time")
        if not sent_time:
            sent_time = get_time()
            logger.debug("generating new timestamp={} ".format(sent_time))
        self._db[auxT][LOG_LAST_SENTTIME] = float(sent_time)
        if delete_old_logs:
            logger.debug("deleting old logs")
            del self._db[logT][:]
            # while self._db[logT]:
            #     self._db[logT].pop()
            # try:
            #     log_t.table.delete().where(
            #         log_t.table.columns.ts <= float(sent_time)
            #     ).execute()
            # except AttributeError:
            #     pass

    def insert_log(self, typo, in_cache, ts=None):
        # type: (str, bool, int) -> None
        """Updates the log with information about typo. Remember, if sk_dict is
        not provided it will insert @typo as typo_id and 0 as relative_entropy.
        Note the default values used in other_info, which is basically what
        is expected for the original password.
        """
        assert self._pw and self._hmac_salt
        # Only log columns:
        # log_columns = set([
        #     'tid', 'edit_dist', 'rel_entropy', 'ts',
        #     'istop5fixable', 'in_cache'
        # ])
        log_info = {
            'tid': compute_id(self._hmac_salt, typo),
            'edit_dist': distance(str(self._pw), str(typo)),
            'rel_entropy': entropy(typo) - self._pwent,
            'ts': ts if ts else get_time(),
            'istop5fixable': is_in_top5_fixes(self._pw, typo),
            'in_cache': in_cache
        }
        try:
            self._db[logT].append(log_info)
        except KeyError:
            self._db[logT] = [log_info]

    def _add_typo_to_waitlist(self, typo):
        """Adds the typo to the waitlist.
        @typo (string) : typo of the user's passwrod
        """
        logger.debug("Adding a new typo to waitlist")
        logger.debug("Adding: {}".format(typo))
        waitlist = self.get_from_auxtdb(WAIT_LIST)  # , yaml.load)
        indexj = int(self.get_from_auxtdb(INDEX_J))  # , int))
        ts = get_time()
        assert indexj < len(waitlist), \
            "Index_j={}, wait-list={}".format(indexj, waitlist)
        waitlist[indexj] = pkencrypt(self.get_pk(), json.dumps([typo, ts]))
        indexj = (indexj + 1) % WAITLIST_SIZE
        self.set_in_auxtdb(WAIT_LIST, waitlist)
        self.set_in_auxtdb(INDEX_J, indexj)
        logger.debug("Typo encrypted.")

    def _decrypt_n_filter_waitlist(self):
        """Decrypts the waitlist and filters out the ones failed validity
        check. After that it combines the typos and returns a list of
        typos sorted by their frequency.

        return: [(typo_i, f_i)]
        """
        filtered_typos = defaultdict(int)
        sk = deserialize_sk(self._sk)
        assert self._pwent, "PW is not initialized: {}".format(self._pwent)
        ignore = set()
        install_id = self.get_installation_id()
        for typo_ctx in self.get_from_auxtdb(WAIT_LIST): # , yaml.load):
            typo_txt = pkdecrypt(sk, typo_ctx)
            typo, ts = yaml.safe_load(typo_txt)
            # starts with installation id, then must be garbage
            if typo.startswith(install_id):
                continue
            self.insert_log(typo, in_cache=False, ts=ts)
            if typo in ignore: continue
            if self.validate(self._pw, typo):
                filtered_typos[typo] += 1
            else:
                logger.debug("Ignoring: {}".format(typo))
                ignore.add(typo)
        logger.info("Waitlist decrypted successfully")
        return sorted(
            filtered_typos.items(), key=lambda a: a[1], reverse=True
        )

    def get_table_size(self, table_name):
        return self._db[table_name].count()

    @staticmethod
    def get_typo_cache_size():
        return CACHE_SIZE

    def get_pk(self):
        """Returns the public key"""
        if not self._pk:
            self._pk = deserialize_pk(self.get_from_auxtdb(ENC_PK))
        return self._pk

    # TODO: More policies
    @staticmethod
    def cache_insert_policy(old_t_c, new_t_c):
        if old_t_c < 0:  # for garbage rows in cache
            return True
        d = old_t_c + new_t_c
        assert d > 0
        rnd = random.randint(0, d-1)
        return rnd <= new_t_c

    def clear_waitlist(self):
        self._fill_waitlist_w_garbage()
        logger.info("Waitlist is deleted.")

    def check_login_count(self, update=False):
        # type: (boolean) -> boolean
        """Keeps track of how many times the user has successfully logged in."""
        count_entry = self.get_from_auxtdb(LOGIN_COUNT) + 1
        if update:
            self.set_in_auxtdb(LOGIN_COUNT, count_entry)
        allowed = count_entry > NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN
        if not allowed:
            logger.info("Checking login count. Allowed = {}".format(allowed))
        return allowed

    def check(self, pw):
        logger.info("Checking entered password.")
        pk = self.get_pk()   # cannot be tampered
        typo_cache = self.get_from_auxtdb(TYPO_CACHE)  # , yaml.load)
        match_found = False
        freq_counts = []
        i = 0
        for i, sk_ctx in enumerate(typo_cache):
            try:
                sk = pwdecrypt(pw, sk_ctx)
                if not verify_pk_sk(pk, bytes(sk)):  # Somehow the hash matched !!
                    logger.error("pk-sk Verification failed!!")
                    continue
                self._sk = sk
            except (TypeError, ValueError) as e: # Decryption Failed
                # print("Failed for {}.{} ({})".format(pw, i, e))
                # that means password did not match.
                continue
            header = yaml.safe_load(
                pkdecrypt(sk, self.get_from_auxtdb(HEADER_CTX))
            )
            self._hmac_salt = urlsafe_b64decode(header[HMAC_SALT])
            freq_counts = header[FREQ_COUNTS]
            if i > 0:
                freq_counts[i-1] += 1
            self._pw = header[REAL_PW]
            self._pwent = entropy(self._pw)
            self.insert_log(pw, in_cache=True, ts=get_time())
            match_found = True
            break
        allowed = False
        if match_found:
            assert self._pwent, "PW is not initialized: {}".format(self._pwent)
            self._update_typo_cache_by_waitlist(typo_cache, freq_counts)
            if i == 0:   # the real password entered
                self.check_login_count(update=True)
                allowed = True
            else:   # A typo entered
                allowed = (self.check_login_count(update=False) and
                           self.is_allowed_login())
        else:
            self._add_typo_to_waitlist(pw)
            allowed = False
        logger.info("TypTop's decision: LoginAllowed = {}".format(allowed))
        return allowed

    def get_from_auxtdb(self, key):
        return self._aux_tab.get(key, '')

    def set_in_auxtdb(self, key, value):
        # type: (string, object) -> None
        self._aux_tab[key] = value

    def validate(self, orig_pw, typo):
        # Edit distance 1 is always allowed for all passwords; more
        # allowance if len(orig_pw) is large
        edit_dist = (distance(str(orig_pw), str(typo))-1)/float(len(orig_pw))
        typo_ent = entropy(typo)
        not_much_weaker = (typo_ent >= (self._pwent - REL_ENT_CUTOFF))
        not_too_weak = (typo_ent >= LOWER_ENT_CUTOFF)
        close_edit = (edit_dist <= EDIT_DIST_CUTOFF)
        return not_too_weak and not_much_weaker and close_edit

    def _update_typo_cache_by_waitlist(self, typo_cache, freq_counts):
        """
        Updates the hash cache according to waitlist and clears the waitlist
        @typo_cache: a list of typos in the cache, and @freq_counts are the
        corresponding frequencies.

        returns: Updated typo_cache and their frequencies. Also applies the
        permutations.
        """
        logger.info("Updating TypoCache by Waitlist")
        good_typo_list = self._decrypt_n_filter_waitlist()
        mini, minf = min(enumerate(freq_counts), key=itemgetter(1))
        for typo, f in good_typo_list:
            if UserTypoDB.cache_insert_policy(minf, f):
                logger.debug("Inserting: {} @ {}".format(typo, mini))
                typo_cache[mini+1] = pwencrypt(typo, self._sk)
                freq_counts[mini] = max(minf + 1, f)  # TODO: Check
                mini, minf = min(enumerate(freq_counts), key=itemgetter(1))
            else:
                logger.debug("I miss you: {} ({} <-> {})".format(typo, minf, f))
                logger.debug("Freq counts: {}".format(freq_counts))

        # write the new typo_cache and freq_list
        # TODO: Apply permutation
        header_ctx = pkencrypt(self._pk, json.dumps({
            REAL_PW: self._pw,
            HMAC_SALT: urlsafe_b64encode(self._hmac_salt),
            FREQ_COUNTS: freq_counts
        }))
        logger.debug("Real pw={!r}".format(self._pw))

        self.set_in_auxtdb(HEADER_CTX, header_ctx)
        self.set_in_auxtdb(TYPO_CACHE, typo_cache)
        self.clear_waitlist()

    def get_prompt(self):
        """This used to supply password prompt, but in new versions,
        this function is useless"""
        # Password prompts
        return {
            SYSTEM_STATUS_ALL_GOOD: 'aDAPTIVE pASSWORD',
            SYSTEM_STATUS_NOT_INITIALIZED: 'Please Initialize',
            SYSTEM_STATUS_PW_CHANGED: 'Please Re-initialize',
            SYSTEM_STATUS_CORRUPTED_DB: 'Corrupted DB!'
        }.get(self.get_from_auxtdb(SYSTEM_STATUS), '(Error!) Password')

    def set_status(self, status):
        self.set_in_auxtdb(key=SYSTEM_STATUS, value=status)


def check_system_status(typo_db):
    sys_stat_val = typo_db.get_from_auxtdb(SYSTEM_STATUS)
    # if reached here - db should be initiated updating the entry count
    if not sys_stat_val:  # if not found in table
        raise UserTypoDB.CorruptedDB(
            "ERROR: (check_system_status) Typtop DB is Corrupted."
        )
    if sys_stat_val == SYSTEM_STATUS_PW_CHANGED:  # password_changed
        raise ValueError(SYSTEM_STATUS_PW_CHANGED)
    if sys_stat_val == SYSTEM_STATUS_CORRUPTED_DB:  # corrupted_db
        raise ValueError(SYSTEM_STATUS_CORRUPTED_DB)


def on_correct_password(typo_db, password):
    # log the entry of the original pwd
    logger.info("-^-")
    try:
        if not typo_db.is_typtop_init():
            logger.error("Typtop DB wasn't initiated yet!")
            typo_db.init_typtop(password)
            # the initialization is now part of the installation process
        check_system_status(typo_db)
        # correct password but db fails to see it
        is_match = typo_db.check(password)
        if not is_match:
            logger.debug("Changing system status to {}.".format(
                SYSTEM_STATUS_PW_CHANGED
            ))
            typo_db.set_status(SYSTEM_STATUS_PW_CHANGED)
            logger.info("Changing the system status because: match={}".format(is_match))
    except (ValueError, KeyError) as e:
        # most probably - an error of decryption as a result of pw change
        typo_db.set_status(SYSTEM_STATUS_PW_CHANGED)
        logger.exception("Key error raised. Probably a failure in decryption. Re-initializing...")
        typo_db.reinit_typtop(password)
    except Exception as e:
        logger.exception(
            "Unexpected error while on_correct_password:\n{}\n"
            .format(e)
        )
    # In order to avoid locking out - always return true for correct password
    return True


def on_wrong_password(typo_db, password):
    logger.info("-\/-")
    is_match = False
    try:
        if not typo_db.is_typtop_init():
            logger.error("Typtop DB wasn't initiated yet!")
            # typo_db.init_typtop(password)
            return False
        check_system_status(typo_db)
        is_match = typo_db.check(password)
        # password has changed and this is an old password
        if is_match and typo_db.is_real_pw(password):
            logger.info("Password changed, old password entered. Re-initializing..")
            typo_db.reinit_typtop(urlsafe_b64encode(os.urandom(16)))
            return False
    except (ValueError, KeyError) as e:
        # probably  failure in decryption
        logger.exception("Error!! Probably failure in decryption. Re-initializing...")
        typo_db.reinit_typtop(password)
    except Exception as e:
        logger.exception("Unexpected error while on_wrong_password:\n{}\n"\
                         .format(e))
        print("TypToP is not initialized.\n $ sudo typtop --init")
    return is_match


def call_check(exchk_ret_val, user, password):
    ret = -1
    # usage = '<1 or 0> <username> <password>'
    if not is_user(user):
        ret = 1
    else:
        typo_db = UserTypoDB(user, debug_mode=TEST)
        exchk_ret_val = str(exchk_ret_val)
        if exchk_ret_val == '0':
            ret = int(not on_correct_password(typo_db, password))
        else:
            ret = int(not on_wrong_password(typo_db, password))
    return ret

if __name__ == "__main__":
    sys.stdout.write("{}".format(call_check(*sys.argv[1:])))
