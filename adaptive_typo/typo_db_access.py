import logging
import dataset
import time
import json
import os
from copy import deepcopy
from zxcvbn import password_strength
from collections import OrderedDict
import pwd
from pw_pkcrypto import (
    encrypt, decrypt, derive_public_key,
    derive_secret_key, update_ctx, compute_id
)

# TODO - check whether we should switch somewhere to "hash_pw"
# TOTO - the same with "match_hashes - or make it faster

import binascii
from word2keypress import distance
from random import random # maybe something else?

DB_NAME = ".typoToler"
ORIG_PW = 'OriginalPw'
ORIG_SK_SALT = 'OriginalPwSaltForEncSecretKey'
ORIG_PW_CTX = 'OrignalPwCtx'
ORIG_PW_ENTROPY_CTX = 'OrgignalPwEntropyCtx'
GLOBAL_SALT_CTX = 'GlobalSaltCtx'

ORIG_PW_ENC_PK = 'EncPublicKey'
ORIG_PW_SGN_PK = 'SgnPublicKey'
ORIG_SGN_SALT = 'OriginalPwSaltForVerifySecretKey'
pks_and_salts_T = "Pwd_pk_t"
PK_DB_PATH = '/etc/adaptive_typo'
PK_DB_NAME = DB_NAME+".ro" # READ_ONLY or ROOT_ONLY

# default values
CACHE_SIZE = 5
EDIT_DIST_CUTOFF = 1

END_OF_SESS = 'END OF SESSION' # for log's use

# Tables' names:
logT = 'Log'
# table cols:   timestamp, t_id, edit_dist, top5fixable,
#               is_in_hash, allowed_login, rel_bit_str
hashCacheT = 'HashCache'
# table cols: H_typo, salt, count, pk, t_id , top5fixable, rel_bit_str'
# 
waitlistT = 'Waitlist'
# table col: base64(enc(json(typo, ts, hash, salt, entropy)))'
auxT = 'AuxSysData' # holds system's setting as well as glob_salt and enc(pw)
# table cols: desc, data



# auxiley info 'desc's:
AllowedTypoLogin = "AllowedTypoLogin"
InstallDate = "InstallDate"
InstallationID = "Install_id"
LastSent="Last_sent"
SendEvery="SendEvery(sec)"
UPDATE_GAPS= 24 * 60 * 60 # 24 hours, in seconds

# LastPwChange = "LastPwChange"  # not yet implemented
# PwTypoPolicy = "PwTypoPolicy"  # not yet implemented
CacheSize = "CacheSize"
# PwAcceptPolicy = "PwAcceptPolicy"   # not yet implemented
EditCutoff = "EditCutoff"  # The edit from which (included) it's too far

#log col:
rel_bit_strength = 'rel_bit_str'

# GENERAL TODO:
# - improve computation speed
# - decide when and whether to check there were no double entries is auxT (pw&globSalt)
# note to self -    if the original pw is given,
#                   it needs to be updated to log independently
#                   the def logging in the functions won't do it


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

def get_entropy_stat(typo):
    return password_strength(typo)['entropy']

class UserTypoDB:

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
        
        self._user = user  # this is a real user.
        homedir = pwd.getpwnam(self._user).pw_dir
        typo_dir = os.path.join(PK_DB_PATH,user)
        if not os.path.exists(typo_dir): # creating dir only if it doesn't exist
            # this directory needs root permission, and should be created as
            # part of the installation process
            try:
                os.makedirs(typo_dir)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise
        self._db_path = "{}/{}.db".format(homedir, DB_NAME)
        self._pk_db_path="{}/{}.db".format(typo_dir,PK_DB_NAME) #
        self._log_path = "{}/{}.log".format(homedir, DB_NAME)
        self._db = dataset.connect('sqlite:///{}'.format(self._db_path))
        self._pk_db = dataset.connect('sqlite:///{}'.format(self._pk_db_path)) #
        self._global_salt = None  # only will be available if correct pw is provided
        # setting the logger object
        log_level = logging.DEBUG if debug_mode else logging.INFO
        setup_logger(self._log_path, log_level)
        info_t = self._db[auxT]
        dataLine_N = info_t.find_one(desc=CacheSize)
        if dataLine_N:
            self.N = int(dataLine_N['data'])
            logger.info("{}: N={}".format(hashCacheT, self.N))
        else:
            self.N =  CACHE_SIZE

        dataLine_IsON = info_t.find_one(desc=AllowedTypoLogin)
        if dataLine_IsON and dataLine_IsON['data'] == 'True':
            self.isON, active = True, "ON"
        else:
            self.isON, active = False, "OFF"
        logger.info("typoToler is {}".format(active))

    def getdb(self):
        return self._db
    
    def get_db_path(self):
        return self._db_path

#    def get_pk_db_path(self): # TODO REMOVE
#        return self._pk_db_path()

    def get_logging_path(self,username):
        homedir = pwd.getpwnam(username).pw_dir
        return "{}/{}.log".format(homedir, DB_NAME)

    
    def is_typotoler_init(self): # TODO CHANGE
        """
        Returns whether the typotoler has been set (might be installed
        but not active)
        """
        infoT = self._db[auxT]
        encPw = infoT.find_one(desc=ORIG_PW_CTX)
        globSalt = infoT.find_one(desc=GLOBAL_SALT_CTX)
        if ((not globSalt) != (not encPw)):
            # if glob and pw aren't in the same initialization state
            if not globSalt:
                stub = 'global salt is missing'
            else:
                stub = 'pw is missing'
            logger.critical('DB is corrupted: {}'.format(stub))
            raise UserTypoDB.CorruptedDB("{} is corrupted!  globSalt={}  encPw={}"\
                            .format(auxT, globSalt, encPw))
        return bool(encPw)

    def allow_login(self, allow=True):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB("Typotoler DB wasn't initiated yet!")
        aux_T = self._db[auxT]
        aux_T.update(dict(desc=AllowedTypoLogin, data="False"), ['desc'])
        self.isON = False
        logger.info("typoToler set to OFF")
        
    def allow_login(self):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self._db[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin, data="True"),['desc'])
        self.isON = True
        logging.getLogger(DB_NAME).info("typoToler set to ON")

    def is_allowed_login(self):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self._db[auxT]
        is_on = sys_aux_T.find_one(desc=AllowedTypoLogin)['data']
        assert is_on in ('True', 'False'), \
            'Corrupted data in {}: {}={}'.format(auxT, AllowedTypoLogin, is_on)
        return is_on == 'True' 

    def init_typotoler(self, pw, N=CACHE_SIZE, maxEditDist=1, typoTolerOn=True):
        """Create the 'typotoler' database in user's home-directory.  Changes the DB
        permission to ensure its only readable by the user.  Also, it intializes
        the required tables as well as the reuired variables, such as, the
        hashCache size, the global salt etc.
        """
        logger.info("Initiating typoToler db with {}".format(
            dict(pw=pw, N=N, maxEditDist=maxEditDist, typoTolerOn=typoTolerOn)
        ))
        u_data = pwd.getpwnam(self._user)
        u_id, g_id = u_data.pw_uid, u_data.pw_gid
        db_path = self._db_path
        pk_db_path = self._pk_db_path
        os.chown(db_path, u_id, g_id)  # change owner to user
        os.chmod(db_path, 0600)  # rw only for owner
        os.chown(pk_db_path,0,0) # TODO CHECK
        os.chmod(pk_db_path,0644) # TODO CHECK
        logger.debug(
            "{} permissons set to RW only for user:{}".format(db_path, self._user)
        )
        db = self._db
        db[auxT].delete()         # make sure there's no old unrelevant data

        # self.init_aux_data(N, typoTolerOn, maxEditDist)
        # *************** Initializing Aux Data *************************
        install_id = binascii.b2a_base64(os.urandom(8))
        install_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        last_sent_time = get_time_str()

        logger.info("Initializing the auxiliary data base ({})".format(auxT))
        db[auxT].insert_many([
            dict(desc=CacheSize, data=str(N)),
            dict(desc=AllowedTypoLogin, data=str(typoTolerOn)),
            dict(desc=EditCutoff, data=str(maxEditDist)),
            dict(desc=InstallationID, data=install_id),
            dict(desc=InstallDate, data=install_time),
            dict(desc=LastSent, data=last_sent_time),
            dict(desc=SendEvery, data=str(UPDATE_GAPS))
        ])
        self.N = N
        self.isON = typoTolerOn
        
        # *************** insert first password and global salt: ********
        info_t = db[auxT] # 
        # TODO REMOVE none relevent as we removed the table:
        #assert not info_t.find_one(desc=ORIG_PW)# ,"Original password is already stored. Weird!!"
                                      

        # 1. derive public_key from the original password 
        enc_pk_salt = os.urandom(16) # salt of enc_pk
        enc_salt_bs64 = binascii.b2a_base64(enc_pk_salt)
        pw_hash, pw_enc_pk = derive_public_key(pw, enc_pk_salt, for_='encryption')
        enc_pk_dict = {ORIG_PW: pw_enc_pk}

        # TODO CHANGE -- use the same salt for both of them
        # 1.5 inserting pks to the table (with their salts?)
        pk_salt_t = self._pk_db[pks_and_salts_T]
        sgn_pk_salt = os.urandom(16)
        sgn_salt_bs64 = binascii.b2a_base64(sgn_pk_salt)
        _, pw_sgn_pk = derive_public_key(pw,sgn_pk_salt,for_='verify')

        # 2. encrypt the global salt with the enc pk
        global_hmac_salt = os.urandom(16)
        global_salt_cipher = binascii.b2a_base64(encrypt(enc_pk_dict, global_hmac_salt))
        
        pw_entropy = encode_encrypt(enc_pk_dict, bytes(get_entropy_stat(pw)))
        pw_cipher = encode_encrypt(enc_pk_dict, pw)
        
        info_t.insert_many([
            dict(desc=ORIG_SK_SALT, data=enc_salt_bs64), 
            dict(desc=ORIG_PW_ENC_PK, data=pw_enc_pk),
            dict(desc=GLOBAL_SALT_CTX, data=global_salt_cipher),
            dict(desc=ORIG_PW_CTX, data=pw_cipher),
            dict(desc=ORIG_PW_ENTROPY_CTX, data=pw_entropy)
        ])
        info_t.create_index(['desc']) # To speed up the queries to the table

        # 2.5
        # note - we can't move any ctx to the 'read-only' pk_salt_t
        # because all ctx needs updating everytime a new typo enters HashCache
        pk_salt_t.insert_many([
            dict(desc=ORIG_SK_SALT, data=enc_salt_bs64), 
            dict(desc=ORIG_PW_ENC_PK, data=pw_enc_pk),
            dict(desc=EditCutoff, data=str(maxEditDist)),
            dict(desc=ORIG_SGN_SALT, data=sgn_salt_bs64),
            dict(desc=ORIG_PW_SGN_PK, data=pw_sgn_pk)
        ]) # in the future will also store the entropy cutOffs TODO
        pk_salt_t.create_index(['desc'])
            

    def is_typotoler_on(self):
        dataLine = self._db[auxT].find_one(desc=AllowedTypoLogin)
        return dataLine and bool(dataLine['data'])
        
    def is_in_top5_fixes(self, orig_pw, typo):
        return orig_pw in (
            typo.capitalize(), typo.swapcase(), typo.lower(), 
            typo.upper(), typo[1:], typo[:-1]
        )


    def get_installation_id(self):
        if not self.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB("Typotoler uninitialized")
        return self._db[auxT].find_one(desc=InstallationID)['data']
 
    def get_last_unsent_logs_iter(self):
        """
        Check what was the last time the log has been sent,
        And returns whether the log should be sent
        """
        if not self.is_typotoler_init():
            return False, iter([])
        aux_t = self._db[auxT]
        last_sending = float(aux_t.find_one(desc=LastSent)['data'])
        update_gap = float(aux_t.find_one(desc=SendEvery)['data'])
        time_now = time.time()
        passed_enough_time = ((time_now - last_sending) >= update_gap)
        if not passed_enough_time:
            logger.debug("Last sent time:{}".format(str(last_sending)))
            logger.debug("Not enought time has passed to send new logs")
            return False, iter([])
        log_t = self._db[logT]
        # print "log t:{}".format(log_t) # TODO REMOVE
        new_logs = log_t.find(log_t.table.columns.ts >= last_sending)
        logger.info("Prepared newe logs to be sent, from {} to {}".format(
            str(last_sending),str(time_now))
        )
        return True, new_logs

    def update_last_log_sent_time(self,sent_time=''):
        if not sent_time:
            sent_time = self.get_time_str()
        self._db[auxT].update(dict(desc=LastSent, data=float(sent_time)), ['desc'])

    def _hmac_id(self, typo, sk_dict):
        """
        Calculates the typo_id required for logging.
        @typo (string) : the typo
        @sk_dict (dict) : is a dictionar from t_h_id -> ECC secret_key, 
        """
        global_salt = self.get_global_salt(sk_dict)
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
        cacheT = self._db[hashCacheT]
        for cacheline in cacheT:
            sa = binascii.a2b_base64(cacheline['salt'])
            hs_bytes, sk = derive_secret_key(typo, sa)
            t_h_id = cacheline['H_typo'] # the hash id is in base64 form
            # Check if the hash(typo, sa) matches the stored hash 
            if binascii.a2b_base64(t_h_id) != hs_bytes: continue

            logger.debug("Typo found in {} (t_h_id={!r})".format(hashCacheT, t_h_id))
            typo_count = cacheline['count']

            # update table with new count
            if increaseCount:
                typo_count += 1
                cacheT.update(dict(H_typo=t_h_id, count=typo_count), ['H_typo'])
            if updateLog:
                self.update_log(typo_id, cacheline)
            return {t_h_id: sk}, True
        logger.debug("Typo wasn't found in {}".format(hashCacheT))
        return {}, False

    def update_log(self, typo, sk_dict={}, other_info={}):
        """Updates the log with information about typo. Remember, if sk_dict is not
        provided it will insert @typo as typo_id and 0 as relative_entropy.
        Note the default values used in other_info, which is basically what is
        expected for the original password.
        """
        other_info['t_id'] = self._hmac_id(typo, sk_dict) if sk_dict else typo
        other_info['ts'] = get_time_str()

        for col in ['editdist', 'top5fixable', 'in_cache', 
                    'allowed_login', 'rel_entropy']:
            if col not in other_info:
                other_info[col] = 0  # Hope it will handle bollean
        self._db[logT].insert(other_info)

    def log_orig_pw_use(self):
        ts = get_time_str()
        self.update_log(ORIG_PW)
                                  
    def log_end_of_session(self):
        ts = get_time_str()
        self._db[logT].insert(dict(t_id=END_OF_SESS, timestamp=ts))

    def log_message(self, msg):
        ts = get_time_str()
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
        info_t = self._db[auxT]
        orig_pw_pk = info_t.find_one(desc=ORIG_PW_ENC_PK)['data']
        pk_dict[ORIG_PW] = orig_pw_pk
        assert len(pk_dict)>0, "PK_dict size is zero!!"
        logger.debug("PK_dict keys: {}".format(pk_dict.keys()))
        return pk_dict

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
        sa = os.urandom(16)
        typo_hs, typo_pk = derive_public_key(typo, sa)
        ts = get_time_str()

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
            #typo_hs = binascii.a2b_base64(typo_info['typo_hs'])
            typo_hs_b64 = typo_info['typo_hs']
            t_pk = typo_info['typo_pk'] #
            typo_entropy = typo_info['typo_ent_str']
            #pk_salt_b64 = binascii.a2b_base64(typo_info["typo_pk_salt"])
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
        dataLine_editDist = self._db[auxT].find_one(desc = EditCutoff)
        if dataLine_editDist == None:
            raise UserTypoDB.NoneInitiatedDB("Edit Dist hadn't been set")
        maxEditDist = int(dataLine_editDist['data'])
        global_salt = self.get_global_salt(sk_dict)
        typo_list = []

        for typo in typoDic.keys():
            ts_list, t_hs_bs64, typo_pk, t_sa_bs64, typo_ent  = typoDic[typo]
            count = len(ts_list)
            editDist = distance(unicode(pw), unicode(typo))
            typo_id = compute_id(bytes(typo.encode('utf-8')), global_salt)
            rel_entropy = typo_ent - pw_entropy

            # writing into log for each ts
            if updateLog:
                for ts in ts_list:
                    self.update_log(
                        typo, sk_dict=sk_dict,
                        other_info={
                            'edit_dist': editDist, 
                            'top5fixable': self.is_in_top5_fixes(pw, typo),
                            'in_cache': False,
                            'allowed_login': False,
                            'rel_entropy': rel_entropy
                        }
                    )

            closeEdit = (editDist <= maxEditDist)
            notMuchWeaker = (rel_entropy >= -3) # TODO change to be 3 from readOnlyTable
            notTooWeak = (typo_ent >= 16)        # TODO change to be 16 from readOnlyTable
            # and to be "True" if not found in aux
            
            if  closeEdit and notMuchWeaker and notTooWeak: # TODO CHANGE !
                typo_list.append({
                    'H_typo': t_hs_bs64,
                    'salt': t_sa_bs64,
                    'count': count,
                    'pk': typo_pk,
                    'edit_dist': editDist,
                    'top5fixable': self.is_in_top5_fixes(pw, typo)
                })
                
            else:
                logger.debug(
                    "{} not entered because editDist:{} and rel_typo_entropy:{}"\
                    .format(typo_id, editDist, rel_entropy)
                )

        return sorted(typo_list, key=lambda x: x['count'], reverse=True)[:self.N]

    def get_table_size(self, tableName):
        return self._db[tableName].count()

    def get_hash_cache_size(self):
        return self.get_table_size(hashCacheT)

    # might not be used...
    def pw_and_glob_salt_have_been_initialized(self):
        tt = self._db[auxT]
        count_pw = tt.count(desc=ORIG_PW)
        count_salt = tt.count(desc=GLOBAL_SALT_CTX)
        if count_pw == 0 and count_res == 0:
            return False
        if count_pw == 1 and count_res == 1:
            return True
        raise UserTypoDB.CorruptedDB("There are {} instants of pw\n".format(count_pw)+
                         "And {} instants of glob_salt\n".format(count_salt)+
                         "instead of 1, 1 - in {}".format(auxT))

    def get_pw_sk_salt(self):
        sk_salt_base64 =  self._db[auxT].find_one(desc=ORIG_SK_SALT)
        assert sk_salt_base64, \
            "{}[{}] = {!r}. It should not be None."\
                .format(auxT, ORIG_SK_SALT, sk_salt_base64)
        return binascii.a2b_base64(sk_salt_base64['data'])

    def get_orig_pw(self, sk_dict):
        '''
        Returns pw, pw's entropy (in bits)
        Mainly used after the user submitted an APPROVED typo,
        and now we need to original pw to calc edit_dist
        and the difference in entropy
        '''
        logger.debug("Getting original pw")
        orig_pw = decode_decrypt(
            sk_dict,
            self._db[auxT].find_one(desc=ORIG_PW_CTX)['data']
        )
        orig_pw_entropy = decode_decrypt(
            sk_dict,
            self._db[auxT].find_one(desc=ORIG_PW_ENTROPY_CTX)['data']
        )
        logger.debug("Fetched original password successfully")
        return orig_pw, float(orig_pw_entropy)

    def get_global_salt(self, sk_dict):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        if not self._global_salt:
            try:
                salt_ctx = self._db[auxT].find_one(desc=GLOBAL_SALT_CTX)['data']
                self._global_salt = decode_decrypt(sk_dict, salt_ctx)
            except ValueError as e:
                logging.debug("Sorry wrong id-sk pair ({}). Couldn't decrypt the salt"\
                              .format(sk_dict))
        return self._global_salt

    # WILL CHANGE
    def cache_insert_policy(self, old_t_c, new_t_c):
        # TODO
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


    def add_top_N_typo_list_to_hash_cache(self, typo_list, sk_dict):
        # TODO - make sure that i updates the way it should
        '''
        updates the hashCacheTable according to the update scheme
        @typo_list (list of dict): a list of dictionary, each dictionary is a
        a row of the typo, with all relevent fields
        '''
        # adding if there's free space
        logger.info("Adding typos from {} to {}".format(waitlistT, hashCacheT))
        hash_cache_size = self.get_hash_cache_size()
        new_typos = len(typo_list)
        emptyPlaces = self.N - hash_cache_size
        addNum = min(emptyPlaces, new_typos)
        logger.debug(
            "N:{}, ADD_NUM: {} , cachSize: {}, new typos: {}, vacant: {}"\
            .format(self.N, addNum, hash_cache_size, new_typos, emptyPlaces)
        )
        
        nextLines = self.get_lowest_M_line_in_hash_cache(new_typos - addNum)
        hashT = self._db[hashCacheT]
        if emptyPlaces > 0:
            hashT.insert_many(typo_list[:addNum]) # TODO

        # need to decide what to do with the rest checking whether the rest are
        # added (TODO)
        for typoDict in typo_list[addNum:]:
            oldLine = next(nextLines)
            if self.cache_insert_policy(oldLine['count'], typoDict['count']):
                typoDict['count'] = oldLine['count'] + 1
                # maybe use update instead TODO
                hashT.delete(H_typo = oldLine['H_typo'])
                # later on maybe use add_many to fasten TODO
                hashT.insert(typoDict)

    def update_aux_ctx(self, sk_dict):
        """
        Assumes that the auxT is ok with both password and global salt
        """
        logger.info("Updating {}".format(auxT))
        infoT = self._db[auxT]
        pk_dict = self.get_approved_pk_dict()
        for field in [ORIG_PW_CTX, GLOBAL_SALT_CTX, ORIG_PW_ENTROPY_CTX]:
            new_ctx = encode_decode_update(
                pk_dict, sk_dict, infoT.find_one(desc=field)['data']
            )
            infoT.update(dict(desc=field, data=new_ctx), ['desc'])
        logger.debug("Aux ctx updated successfully: {}".format(len(pk_dict)))

    def clear_waitlist(self):
        self._db[waitlistT].delete()
        logger.info("{} had been deleted".format(waitlistT))

    def original_password_entered(self, pw, updateLog = True):
        if updateLog:
            self.log_orig_pw_use()
        logger.info("Original password had been entered by user")
        pw_salt = self.get_pw_sk_salt()
        logger.debug("Deriving secret key of the password")
        _, pw_sk = derive_secret_key(pw, pw_salt)
        self.update_hash_cache_by_waitlist({ORIG_PW: pw_sk}, updateLog)

        
    def update_hash_cache_by_waitlist(self, sk_dict, updateLog = True):
        """
        Updates the hash cache according to waitlist.
        It also updates the log accordingly (if updateLog is set)
        and clears waitlist

        @updateLog (bool) : whether to update in the log, set to True
        """
        logger.info("Updating {} by {}".format(hashCacheT,waitlistT))
        waitlistTypoDict = self.decrypt_waitlist(sk_dict)
        orig_pw, pw_entropy = self.get_orig_pw(sk_dict)
        topNList = self.get_top_N_typos_within_distance(
            waitlistTypoDict, orig_pw, pw_entropy, sk_dict, updateLog
        )
        self.add_top_N_typo_list_to_hash_cache(topNList, sk_dict)
        # update the ctx of the original password and the global salt because
        # HashCache hash Changed
        self.update_aux_ctx(sk_dict)
        self.clear_waitlist()

def on_correct_password(typo_db, password):
    logger.info("sm_auth: it's the right password") #TODO REMOVE
    # log the entry of the original pwd
    try:
        if not typo_db.is_typotoler_init():
            raise UserTypoDB.NoneInitiatedDB("Typotoler DB wasn't initiated yet!")
            # the initialization is now part of the installation process

        #    typo_db.init_typotoler(password, CACHE_SIZE)
        typo_db.original_password_entered(password) # also updates the log
    except UserTypoDB.CorruptedDB as e:
        # DB is corrupted, restart it
        # TODO 
        pass
    except ValueError as e:
        # probably  failre in decryption
        pass

    except Exception as e:
        logger.Error("Unexpected error while on_correct_password:\n{}\n".format(
            e.message()))
    # in order to avoid locking out - always return true for correct password
    finally:
        return True


def on_wrong_password(typo_db, password):
    try:
        sk_dict, is_in = typo_db.fetch_from_cache(password) # also updates the log
        if not is_in: # aka it's not in the cache, 
            logger.info("a new typo appeared!") # TODO REMOVE
            typo_db.add_typo_to_waitlist(password)
            return False
        else: # it's in cach
            logger.info("typo in cach") # TODO REMOVE
            typo_db.update_hash_cache_by_waitlist(sk_dict) # also updates the log
            if typo_db.is_typotoler_on():
                logger.info("Returning SUCEESS TypoToler")
                return True
            else:
                logger.info("but typoToler is OFF") # TODO REMOVE
                return False
    except ValueError as e:
        # probably  failre in decryption
        logger.Error("ValueError:{}".format(e.message()))
        pass
    except UserTypoDB.CorruptedDB as e:
        # DB is corrupted, restart it
        pass
    except Exception as e:
        logger.Error("Unexpected error while on_correct_password:\n{}\n".format(
            e.message()))
    # if reached here it means there was some kind of an error.
    # returns False to be on the safe side
    finally:
        return False
        


