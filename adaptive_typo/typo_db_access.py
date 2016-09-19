import logging
import dataset
import sys # TODO DELETE
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

LOGGER_NAME = "typoToler"
DB_NAME = "typoToler"
ORIG_PW = 'OriginalPw'
ORIG_SK_SALT = 'OriginalPwSaltForSecretKey'
ORIG_PW_CTX = 'OrgignalPwCtx'       # original password's t_id
ORIG_PW_ENTROPY_CTX = 'OrgignalPwEntropyCtx'       # original password's t_id
GLOBAL_SALT_CTX = 'GlobalSaltCtx'   # global salt's t_id
ORIG_PW_PK = 'PublicKey'

# default values
CACHE_SIZE = 5
EDIT_DIST_CUTOFF = 1

END_OF_SESS = 'END OF SESSION' # for log's use

# Tables' names:
logT = 'Log'
# table cols:   timestamp, t_id, edit_dist, top_5_fixes,
#               is_in_hash, allowed_login, rel_bit_str
hashCacheT = 'HashCache'
# table cols: H_typo, salt, count, pk, t_id , top_5_fixes, rel_bit_str'
# 

waitlistT = 'Waitlist'
# table col: base64(enc(json(typo, ts, hash, salt, entropy)))'
auxT = 'AuxSysData' # holds system's setting as well as glob_salt and enc(pw)
# table cols: desc, data
#             pk, pk_salt, ctx
# TODO - maybe we should have the ctx data in 'data'

# auxiley info 'desc's:
AllowedTypoLogin = "AllowedTypoLogin"
InstallDate = "InstallDate"
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


logger = logging.getLogger(LOGGER_NAME)
def setup_logger(logfile_path, log_level):
    logger.setLevel(log_level)
    if not logger.handlers:  # if it doesn't have an handler yet:
        handler = logging.FileHandler(logfile_path)
        formatter = logging.Formatter('%(asctime)s + %(levelname)s + %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

def encode_encrypt(pk_dict, msg):
    return binascii.b2a_base64(encrypt(pk_dict, msg))

def decode_decrypt(sk_dict, ctx):
    return decrypt(sk_dict, binascii.a2b_base64(ctx))

CONFIG_FILE = "typodb.cfg"
class UserTypoDB:
    
    def __str__(self):
        return "UserTypoDB ({})".format(self._user)

    def __init__(self, user, debug_mode=False):
        
        self._user = user  # this is a real user.
        homedir = pwd.getpwnam(self._user).pw_dir 
        self._db_path = "{}/{}.db".format(homedir, DB_NAME)
        self._log_path = "{}/{}.log".format(homedir, DB_NAME)
        self._db = dataset.connect('sqlite:///{}'.format(self._db_path))

        # setting the logger object
        log_level = logging.DEBUG if debug_mode else logging.INFO
        setup_logger(self._log_path, log_level)

        if debug_mode: # TODO REMOVE
            print "should log" # TODO REMOVE
        logger.debug("{} created".format(str(self)))
        
        info_t = self._db[auxT]
        dataLine_N = info_t.find_one(desc=CacheSize)
        if dataLine_N:
            self.N = int(dataLine_N['data'])
            logger.debug(" N, {}'s size is {}".format(hashCacheT, self.N))
        else:
            self.N =  CACHE_SIZE

        dataLine_IsON = info_t.find_one(desc=AllowedTypoLogin)
        if dataLine_IsON and dataLine_IsON['data'] == 'True':
            self.isON, active = True, "ON"
        else:
            self.isON, active = False, "OFF"
        logger.info("typoToler is {}".format(active))

    def getdb(self):
        """
        Returns the db
        If the db hasn't been connected yet - it connects to it
        """
        return self._db
    
    def get_db_path(self, username):
        return self._db_path

    def get_logging_path(self,username):
        homedir = pwd.getpwnam(username).pw_dir
        return "{}/{}.log".format(homedir,DB_NAME)
    

    def is_typotoler_init(self):
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
            raise Exception("{} is corrupted!  globSalt={}  encPw={}"\
                            .format(auxT, globSalt, encPw))
        return bool(encPw)

    def disallow_login(self):
        # logger = logging.getLogger(LOGGER_NAME)
        if not self.is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self._db[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin, data="False"), ['desc'])
        self.isON = False
        logger.info("typoToler set to OFF")
        

    def allow_login(self):
        if not self.is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self._db[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin, data="True"),['desc'])
        self.isON = True
        logging.getLogger(LOGGER_NAME).info("typoToler set to ON")

    def is_allowed_login(self):
        if not self.is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self._db[auxT]
        is_on = sys_aux_T.find_one(desc=AllowedTypoLogin)['data']
        if is_on != 'True' and is_on != 'False':
            raise Exception('Corrupted data in {}:{}, value:{}'.format(
                auxT, AllowedTypoLogin, is_on))
        return is_on == 'True' 

    def init_typotoler(self, pw, N, maxEditDist=1, typoTolerOn=True):
        """Create the 'typotoler' database in user's home-directory.  Changes the DB
        permission to ensure its only readable by the user.  Also, it intializes
        the required tables as well as the reuired variables, such as, the
        hashCache size, the global salt etc.
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Initiating typoToler db with {}".format(
            dict(pw=pw, N=N, maxEditDist=maxEditDist, typoTolerOn=typoTolerOn)
        ))
        u_data = pwd.getpwnam(self._user)
        u_id, g_id = u_data.pw_uid, u_data.pw_gid
        db_path = self._db_path
        os.chown(db_path, u_id, g_id)  # change owner to user
        os.chmod(db_path, 0600)  # rw only for owner

        logger.debug(
            "{} permissons set to RW only for user:{}".format(db_path, self._user)
        )
        db = self._db
        db[auxT].delete()         # make sure there's no old unrelevant data

        # self.init_aux_data(N, typoTolerOn, maxEditDist)
        # *************** Initializing Aux Data *************************
        logger.info("Initializing the auxiliary data base ({})".format(auxT))
        
        db[auxT].insert_many([
            dict(desc=CacheSize, data=str(N)),
            dict(desc=AllowedTypoLogin, data=str(typoTolerOn)),
            dict(desc=EditCutoff, data=str(maxEditDist))
        ])
        self.N = N
        self.isON = typoTolerOn
        
        # *************** insert first password and global salt: ********
        logger.debug("Inserting first pw and glob salt")
        info_t = db[auxT]
        assert not info_t.find_one(desc=ORIG_PW),\
            "Original password is already stored. Weird!!"

        # 1. derive public_key from the original password 
        pk_salt = os.urandom(16)
        pk_salt_base64 = binascii.b2a_base64(pk_salt)
        pw_hash, pw_pk = derive_public_key(pw, pk_salt)
        pk_dict = {ORIG_PW: pw_pk}

        # encrypt the global salt with the pk
        global_hmac_salt = os.urandom(16)
        global_salt_cipher = binascii.b2a_base64(encrypt(pk_dict, global_hmac_salt))
        
        pw_entropy = encode_encrypt(pk_dict, bytes(self.get_entropy_stat(pw)))
        pw_cipher = encode_encrypt(pk_dict, pw)
        
        info_t.insert_many([
            # ORIG_SK_SALT will be used to derive secret key later
            dict(desc=ORIG_SK_SALT, data=pk_salt_base64), 
            dict(desc=ORIG_PW_PK, data=pw_pk),
            dict(desc=GLOBAL_SALT_CTX, data=global_salt_cipher),
            dict(desc=ORIG_PW_CTX, data=pw_cipher),
            dict(desc=ORIG_PW_ENTROPY_CTX, data=pw_entropy)
        ])
        info_t.create_index(['desc']) # To speed up the queries to the table
        logger.debug("Pw and glob salt inserted successfully")
        logger.info("TypoToler initiated succesfully")
        
    def is_typotoler_on(self):
        dataLine = self._db[auxT].find_one(desc=AllowedTypoLogin)
        return dataLine and bool(dataLine['data'])
        
    def is_in_top_5_fixes(self, orig_pw, typo):
        return orig_pw in (
            typo.capitalize(), typo.swapcase(), typo.lower(), 
            typo.upper(), typo[1:], typo[:-1]
        )

    def compute_id_and_relentropy(self, typo, t_h_id, sk):
        """
        Calculates the typo_id and relative entropy.
        since if does the whole process of fetching needed information
        in case of multiple computations, it'd be better NOT to use this
        function

        @typo (string) : the typo
        @t_h_id (hex string): the hash of the typo, serves as id for sk dict
        @sk (ECC key) : the secret key of the typo
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("Computing id and relative entropy for typo")
        pw, pw_ent = self.get_orig_pw(t_h_id, sk)
        global_salt = self.get_global_salt(t_h_id, sk)
        typo_id = compute_id(btyes(typo.encode('utf-8')), global_salt)
        typo_ent = self.get_entropy_stat(typo)
        rel_ent = typo_ent - pw_ent
        logger.debug("computed typo id:{}, and relative entropy:{}".format(
            typo_id,rel_ent))
        return typo_id, rel_ent
    
    def fetch_from_cache(self, typo, increaseCount=True, updateLog=True):
        '''
        Returns typo's pk, typo's HASH ID, True if it's in HashCach
        If not - return "","", False
        By default:
            - increase the typo count
            - write the relevant log
        @typo (string) : the given password typo
        @increaseCount (bool) : whether to update the typo's count if found
        @updateLog (bool) : whether to insert an update to the log
        '''
        logger.debug("Searching for typo in {}".format(hashCacheT))
        ts = self.get_time_str()
        cachT = self._db[hashCacheT]
        for cacheline in cachT:
            sa = binascii.a2b_base64(cacheline['salt'])
            hs_bytes, sk = derive_secret_key(typo, sa)
            t_h_id = cacheline['H_typo'] # the hash id is in base64 form
            hsInTable = binascii.a2b_base64(t_h_id)
            if hsInTable != hs_bytes: continue

            # we removed the typo_id from the hashCache for security reasons
            # so it (as well as the difference in entropy) needs to be 
            # calculated every time - only if it is actually found

            logger.debug("Typo found in {}".format(hashCacheT))
            editDist = cacheline['edit_dist']
            isInTop5 = cacheline['top_5_fixes']
            typo_count = cacheline['count']
            typo_id, rel_typo_str = self.compute_id_and_relentropy(typo, t_h_id, sk)
            # update table with new count
            if increaseCount:
                logger.debug("Typo's count had been increased")
                typo_count += 1
                cachT.update(dict(H_typo=t_h_id, count=typo_count), ['H_typo'])
            if updateLog:
                self.update_log(
                    ts, typo_id, editDist, rel_typo_str, isInTop5,'True', 
                    str(self.isON)
                )
            return sk, t_h_id, True
        logger.debug("Typo wasn't found in {}".format(hashCacheT))
        return '', '', False

    def update_log(self, ts, typoID_or_msg, editDist, 
                   rel_typo_ent_str, isInTop5, isInHash, allowedLogin):
        log_t = self._db[logT]
        log_t.insert(dict(
            t_id=typoID_or_msg, 
            timestamp=ts, 
            edit_dist=editDist,
            top_5_fixes=isInTop5, 
            is_in_hash=isInHash,
            allowed_login=allowedLogin, 
            rel_typo_str=rel_typo_ent_str
        ))

    def log_orig_pw_use(self):
        ts = self.get_time_str()
        self.update_log(ts, ORIG_PW,'0','0','False','False','True')
                                  
    def log_end_of_session(self):
        ts = self.get_time_str()
        self._db[logT].insert(dict(t_id=END_OF_SESS, timestamp=ts))

    def log_message(self, msg):
        ts = self.get_time_str()
        self._db[logT].insert(dict(t_id=msg, timestamp=ts))
        
    def get_approved_pk_dict(self):
        '''
        Returns a dict of pw'->pk
        for all approved typos and the original pw

        for the typos, the ids are the base64 of their hashes in HashCache
        '''
        logger.debug("Getting approved pk dictionary")
        db = self._db
        cachT = db[hashCacheT]
        pk_dict = {}
        
        # all approved typos' pk
        logger.debug("Getting from {}".format(hashCacheT)) 
        for cachLine in cachT:
            typo_h_id = cachLine['H_typo'].encode('utf-8') # TODO remove encoding?

            # the typo ids for the purpose of pk_dict are the base64 of their
            # hashes (RC: Why not use one single kind of id)

            typo_pk = cachLine['pk']
            logger.debug("Got {}'s pk:{}".format(typo_h_id,typo_pk))
            # pk is a string so can be stored as is in the table as is
            pk_dict[typo_h_id] = typo_pk
        
        # original pw's pk
        logger.debug("Getting from {}".format(auxT))
        info_t = db[auxT]
        orig_pw_pk = info_t.find_one(desc=ORIG_PW_PK)['data']
        logger.debug("Got {}'s pk:{}".format(ORIG_PW, orig_pw_pk))
        pk_dict[ORIG_PW] = orig_pw_pk
        assert len(pk_dict)>0, "PK_dict size is zero!!"
        logger.debug("The pk dictionary was drawn successfully")
        return pk_dict

    def get_time_str(self):
        """
        Returns the timestamp in a string, in a consistent format
        which works in linux and can be stored in the DB
        (unlike datetime.datetime, for example)
        """
        return str(time.time())

    def get_entropy_stat(self, typo):
        return password_strength(typo)['entropy']

    def add_typo_to_waitlist(self, typo):
        """
        Adds the typo to the waitlist.
        saves the timestamp as well (for logging reasons)
        **** for now: (might be change from computation time reasons) ****
        computes an hash for the typo (+sa)
        encryptes everything in a json format
        enc(json(dict(...)))
        dictionary keys: typo_hs, typo_pk, typo_pk_salt, timestamp, typo

        @typo (string) : the user's passwrod typo
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Adding typo to waitlist")
        # should ts be encrypted as well?
        sa = os.urandom(16)
        typo_hs, typo_pk = derive_public_key(typo, sa)

        ts = self.get_time_str()
        typo_str = self.get_entropy_stat(typo)
        plainInfo = json.dumps({
            "typo_hs": binascii.b2a_base64(typo_hs),
            "typo_pk": typo_pk, #
            "typo_pk_salt": binascii.b2a_base64(sa),
            "timestamp": ts,
            "typo": typo,
            'typo_ent_str': typo_str
        })
        pk_dict = self.get_approved_pk_dict()
        info_ctx = binascii.b2a_base64(encrypt(pk_dict, plainInfo))
        logger.debug("Typo encrypted successfully")
        logger.debug("{}".format(info_ctx)) # TODO - yes/no?
        
        db = self._db
        w_list_T = db[waitlistT]

        w_list_T.insert(dict(ctx = info_ctx))
        logger.debug("Typo inserted successfully")

    def decrypt_waitlist(self, t_id, t_sk):
        '''
        Returns a dictionary of the typos in waitlist, unsorted,
        Key = typo (string)
        Value = (typo, t_count, ts_list, typo_hs, t_pk, t_pk_salt)
        '''
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Decrypting waitlist")
        new_typo_dic = {}
        sk_dic = {t_id: t_sk}
        for line in self._db[waitlistT].all():
            bin_ctx = binascii.a2b_base64(line['ctx'])
            typo_info = json.loads(decrypt(sk_dic, bin_ctx))
            ts = typo_info['timestamp']
            typo = typo_info['typo']
            #typo_hs = binascii.a2b_base64(typo_info['typo_hs'])
            typo_hs_b64 = typo_info['typo_hs']
            t_pk = typo_info['typo_pk'] #
            typo_str = typo_info['typo_ent_str']
            #pk_salt_b64 = binascii.a2b_base64(typo_info["typo_pk_salt"])
            pk_salt_b64 = typo_info["typo_pk_salt"]
            logger.debug("Decrypted line and got all necessary information")
            if typo not in new_typo_dic:
                new_typo_dic[typo] = ([ts], typo_hs_b64, t_pk,
                                      pk_salt_b64, typo_str)
            else:
                new_typo_dic[typo][0].append(ts) # appending ts to ts_list

        logger.debug("Waitlist decrypted successfully")
        return new_typo_dic

    def get_top_N_typos_within_distance(self, typoDic, pw, pw_entropy,
                                        t_id, t_sk, updateLog=True):
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
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("getting the top N typos within edit distance")
        dataLine_editDist = self._db[auxT].find_one(desc = EditCutoff)
        if dataLine_editDist == None:
            raise Exception("Edit Dist hadn't been set")
        maxEditDist = int(dataLine_editDist['data'])
        global_salt = self.get_global_salt(t_id, t_sk)
        typo_list = []

        for typo in typoDic.keys():
            ts_list, t_hs_bs64, typo_pk, t_sa_bs64, typo_ent  = typoDic[typo]
            count = len(ts_list)
            editDist = distance(unicode(pw), unicode(typo))
            typo_id = compute_id(typo.encode('utf-8'), global_salt)
            isTop5Fixes = str(self.is_in_top_5_fixes(pw, typo))
            rel_typo_str = typo_ent - pw_entropy ###
            # will add it to the information inserted in the list append

            # writing into log for each ts
            if updateLog:
                for ts in ts_list:
                    # if typo got into waitlist - it's not in cache and not
                    # allowed login
                    self.update_log(ts, typo_id, editDist, rel_typo_str,
                                    isTop5Fixes, 'False', 'False')

            closeEdit = editDist <= maxEditDist
            notMuchWeaker = rel_typo_str >= -3 # TODO change to be 3 from aux
            notTooWeak = typo_ent >= 16        # TODO change to be 16 from aux
            # and to be "True" if not found in aux
            
            if  closeEdit and notMuchWeaker and notTooWeak: # TODO CHANGE !
                typo_dic_obj = {
                    'H_typo': t_hs_bs64,
                    'salt': t_sa_bs64,
                    'count': count,
                    'pk': typo_pk,
                    'edit_dist': editDist,
                    'top_5_fixes': isTop5Fixes
                } #'t_id':typo_id, removing t_id from hashCache TODO
                typo_list.append(typo_dic_obj)
            else:
                logger.debug("{} not entered because editDist:{}"+\
                              "and rel_typo_entropy:{}".format(typo_id,editDist,
                                                            rel_typo_str))

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
        raise ValueError("There are {} instants of pw\n".format(count_pw)+
                         "And {} instants of glob_salt\n".format(count_salt)+
                         "instead of 1, 1 - in {}".format(auxT))

    def get_pw_sk_salt(self):
        sk_salt_base64 =  self._db[auxT].find_one(desc=ORIG_SK_SALT)
        assert sk_salt_base64, \
            "{}[{}] = {!r}. It should not be None."\
                .format(auxT, ORIG_SK_SALT, sk_salt_base64)
        return binascii.a2b_base64(sk_salt_base64['data'])

    def get_orig_pw(self, t_h_id, t_sk):
        '''
        Returns pw, pw's entropy (in bits)
        Mainly used after the user submitted an APPROVED typo,
        and now we need to original pw to calc edit_dist
        and the difference in entropy
        '''
        logger.debug("Getting original pw")
        orig_pw = decode_decrypt(
            {t_h_id: t_sk}, 
            self._db[auxT].find_one(desc=ORIG_PW_CTX)['data']
        )
        orig_pw_entropy = decode_decrypt(
            {t_h_id: t_sk}, 
            self._db[auxT].find_one(desc=ORIG_PW_ENTROPY_CTX)['data']
        )
        logger.debug("Fetched original password successfully")
        return orig_pw, float(orig_pw_entropy)

    def get_global_salt(self, t_id, sk):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("Getting global hmac salt")
        salt_ctx = self._db[auxT].find_one(desc=GLOBAL_SALT_CTX)['data']
        salt = decode_decrypt({t_id: sk}, salt_ctx)
        logger.debug("Fetched global salt successfully")
        return salt

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


    def add_top_N_typo_list_to_hash_cache(self, typo_list, t_h_id, t_sk):
        # TODO - make sure that i updates the way it should
        '''
        updates the hashCacheTable according to the update scheme
        @typo_list (list of dict): a list of dictionary, each dictionary is a
        a row of the typo, with all relevent fields
        '''
        # right now it uses certain scheme, we should change it later on

        # adding if there's free space
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Adding typos from {} to {}".format(waitlistT,hashCacheT))
        hash_cache_size = self.get_hash_cache_size()
        new_typos = len(typo_list)
        emptyPlaces = self.N - hash_cache_size
        addNum = min(emptyPlaces, new_typos)
        info_str =  "N:{}, ADD_NUM: {} , cachSize: {}, new typos: {}, vacant: {}".format(
            self.N, addNum, hash_cache_size, new_typos, emptyPlaces)
        logger.debug(info_str)
        
        #if addNum > 0:
        nextLines = self.get_lowest_M_line_in_hash_cache(new_typos - addNum)
        db = self._db
        hashT = db[hashCacheT]
        if emptyPlaces > 0:
            hashT.insert_many(typo_list[:addNum]) # TODO

        # need to decide what to do with the rest
        # checking whether the rest are added
        # TODO 
        for typoDict in typo_list[addNum:]:
            oldLine = next(nextLines)
            if self.cache_insert_policy(oldLine['count'], typoDict['count']):
                typoDict['count'] = oldLine['count'] + 1 #
                hashT.delete(H_typo = oldLine['H_typo']) # maybe use update instead TODO
                hashT.insert(typoDict)     # later on maybe use add_many to fasten TODO

        # update the ctx of the original password and the global salt
        # because HashCache hash Changed
        self.update_aux_ctx(t_h_id, t_sk)

    def update_aux_ctx(self, t_h_id, t_sk):
        """
        Assumes that the auxT is ok with both password and global salt
        """
        logger.info("Updating {}".format(auxT))
        infoT = self._db[auxT]
        pk_dict = self.get_approved_pk_dict()
        sk_dict = {t_h_id: t_sk}

        # or we could just recall 'get_approved_pk_dict' the reason for the
        # double copy is that encrypt changes the given dict
        pk_dict2 = deepcopy(pk_dict) 

        pwCtx = binascii.a2b_base64(infoT.find_one(desc=ORIG_PW_CTX)['data'])
        globSaltCtx = binascii.a2b_base64(infoT.find_one(desc=GLOBAL_SALT_CTX)['data'])

        newPwCtx = binascii.b2a_base64(update_ctx(pk_dict, sk_dict, pwCtx))
        newGlobSaltCtx = binascii.b2a_base64(update_ctx(pk_dict2, sk_dict, globSaltCtx))
        infoT.update(dict(desc=ORIG_PW_CTX, ctx=newPwCtx), ['desc'])
        infoT.update(dict(desc=GLOBAL_SALT_CTX, ctx=newGlobSaltCtx), ['desc'])

        logger.debug("Aux ctx updated successfully")

        
    def clear_waitlist(self):
        self._db[waitlistT].delete()
        # logger.info("{} had been deleted".format(waitlistT))
        logging.getLogger(LOGGER_NAME).info("{} had been deleted".format(waitlistT))

    def original_password_entered(self, pw, updateLog = True):
        if updateLog:
            self.log_orig_pw_use()
        logger.info("Original password had been entered by user")
        pw_salt = self.get_pw_sk_salt()
        logger.debug("Deriving secret key of the password")
        _, pw_sk = derive_secret_key(pw, pw_salt)
        self.update_hash_cache_by_waitlist(ORIG_PW, pw_sk, updateLog)

        
    def update_hash_cache_by_waitlist(self, t_h_id, t_sk, updateLog = True):
        """
        Updates the hash cache according to waitlist.
        It also updates the log accordingly (if updateLog is set)
        and clears waitlist

        @updateLog (bool) : whether to update in the log, set to True
        """
        logger.info("Updating {} by {}".format(hashCacheT,waitlistT))
        waitlistTypoDict = self.decrypt_waitlist(t_h_id, t_sk)
        orig_pw, pw_entropy = self.get_orig_pw(t_h_id, t_sk)
        topNList = self.get_top_N_typos_within_distance(
            waitlistTypoDict, orig_pw, pw_entropy, t_h_id, t_sk, updateLog
        )
        self.add_top_N_typo_list_to_hash_cache(topNList, t_h_id, t_sk)
        self.clear_waitlist()

