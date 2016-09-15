import logging
import dataset
import sys # TODO DELETE
import time
import json
import os
from copy import deepcopy
from zxcvbn import password_strength
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
ORG_PW = 'org_pw'       # original password's t_id
GLOB_SALT = 'glob_saltupda'   # global salt's t_id
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
class UserTypoDB:
    DB_obj = None
    
    def __str__(self):
        return "UserTypoDB ({})".format(self.user)

    def __init__(self, user, debug_mode=False):
        
        self.user = user

        # setting the logger object
        log_level = logging.DEBUG
        if not debug_mode:
            log_level = logging.INFO
        # logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(log_level)
        if not logger.handlers:  # if it doesn't have an handler yet:
            handler = logging.FileHandler(self.get_logging_path(user))
            formatter = logging.Formatter('%(asctime)s + %(levelname)s + %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
##        logger.basicConfig(filename=self.get_logging_path(user),
##                            format='%(asctime)s + %(levelname)s + %(message)s',
##                            level=log_level)
        if debug_mode: # TODO REMOVE
            print "should log" # TODO REMOVE
        logger.debug("{} created".format(str(self)))
        
        info_t = self.getDB()[auxT]
        dataLine_N = info_t.find_one(desc = CacheSize)
        #if dataLineN != None: # TODO REMOVE
        if dataLine_N:
            self.N = int(dataLine_N['data'])
            logger.debug(" N, {}'s size is {}".format(hashCacheT,self.N))
        dataLine_IsON = info_t.find_one(desc=AllowedTypoLogin)
        #if dataLine_IsON != None: # TODO REMOVE
        if dataLine_IsON:
            self.isON = dataLine_IsON['data'] == 'True'
            active = "ON"
            if not self.isON:
                active = "OFF"
            logger.info("typoToler is {}".format(active))

    def getDB(self):
        """
        Returns the db
        If the db hasn't been connected yet - it connects to it
        """
        # logger = logging.getLogger(LOGGER_NAME)
        if not self.DB_obj:
            self.DB_obj = dataset.connect("sqlite:////home/{}/{}.db"\
                               .format(self.user, DB_NAME))
            logger.info("connected to DB")
        return self.DB_obj
    
    def get_DB_path(self, username):
        homedir = pwd.getpwnam(username).pw_dir
        return "{}/{}.db".format(homedir, DB_NAME)

    def get_logging_path(self,username):
        homedir = pwd.getpwnam(username).pw_dir
        return "{}/{}.log".format(homedir,DB_NAME)

    

    def is_typotoler_init(self):
        """
        Returns whether the typotoler has been set (might be installed
        but not active)
        """
        # logger = logging.getLogger(LOGGER_NAME)
        infoT = self.getDB()[auxT]
        encPw = infoT.find_one(desc=ORG_PW)
        globSalt = infoT.find_one(desc=GLOB_SALT)
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
        sys_aux_T = self.getDB()[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin, data="False"), ['desc'])
        self.isON = False
        logger.info("typoToler set to OFF")
        

    def allow_login(self):
        if not self.is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self.getDB()[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin, data="True"),['desc'])
        self.isON = True
        logging.getLogger(LOGGER_NAME).info("typoToler set to ON")

    def is_allowed_login(self):
        if not self.is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self.getDB()[auxT]
        is_on = sys_aux_T.find_one(desc=AllowedTypoLogin)['data']
        if is_on != 'True' and is_on != 'False':
            raise Exception('Corrupted data in {}:{}, value:{}'.format(
                auxT, AllowedTypoLogin, is_on))
        return is_on == 'True' 

    def init_typotoler(self, pw, N, maxEditDist = 1, typoTolerOn = True):
        """Create the 'typotoler' database in user's home-directory.  Changes the DB
        permission to ensure its only readable by the user.  Also, it intializes
        the required tables as well as the reuired variables, such as, the
        hashCache size, the global salt etc.

        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("initiating typoToler")
        username = self.user
        u_data = pwd.getpwnam(username)
        u_id = u_data.pw_uid
        g_id = u_data.pw_gid
        db_path = self.get_DB_path(username)
        os.chown(db_path, u_id, g_id)  # change owner to user
        os.chmod(db_path, 0600)  # rw only for owner
        # self.init_tables(pw, N)
        logger.debug("{} permissons set to RW only for user:{}".format(
            db_path,username))
        db = self.getDB()
        db[auxT].delete()         # make sure there's no old unrelevant data

        # self.init_aux_data(N, typoTolerOn, maxEditDist)
        # *************** Initializing Aux Data *************************
        logger.info("Initializing the auxiliary data base ({})".format(auxT))
        
        info_t = db[auxT]
        if info_t.find_one(desc=AllowedTypoLogin):
            raise Exception("Initial aux data have already been inserted")
        info_t.insert(dict(desc=CacheSize, data=str(N)))
        self.N = N # TODO - dynamically set?
        info_t.insert(dict(desc=AllowedTypoLogin, data=str(typoTolerOn)))
        self.isON = typoTolerOn
        info_t.insert(dict(desc=EditCutoff, data=str(maxEditDist)))
        

        # *************** insert first password and global salt: ********
        logger.debug("Inserting first pw and glob salt")
        db = self.getDB()
        info_t = db[auxT]
        assert not info_t.find_one(desc=ORG_PW),\
            "Original password is already stored. Weird!!"

        pw_salt_pk = os.urandom(16)
        pw_hash, pw_pk = derive_public_key(pw, pw_salt_pk)

        glob_salt_hmac = os.urandom(16)
        self.glob_salt_tmp = glob_salt_hmac # TODO REMOVE

        pw_salt_base64 = binascii.b2a_base64(pw_salt_pk)

        pw_entropy = self.get_entropy_stat(pw) ###
        pw_json = json.dumps({'pw': pw, 'entropy': pw_entropy})

        pk_dict = {ORG_PW: pw_pk}
        pw_json_cipher = binascii.b2a_base64(encrypt(pk_dict, pw_json))
        
        glob_salt_cipher = binascii.b2a_base64(encrypt(pk_dict, glob_salt_hmac))

        # TODO - change it to be 'data' instead of 'ctx'
        info_t.insert(dict(ctx=pw_json_cipher, pk=pw_pk, pk_salt=pw_salt_base64,
                           desc=ORG_PW))
        info_t.insert(dict(ctx=glob_salt_cipher, desc=GLOB_SALT))
        logger.debug("Pw and glob salt inserted successfully")
        logger.info("TypoToler initiated succesfully")
        return
        
    def is_typotoler_on(self):
        dataLine = self.getDB()[auxT].find_one(desc=AllowedTypoLogin)
        if not dataLine:
            return False
        return bool(dataLine['data'])
        
    def is_in_top_5_fixes(self, orig_pw, typo):
        return orig_pw in (typo.capitalize(),
                           typo.swapcase(),
                           typo.lower(), 
                           typo.upper(),
                           typo[1:],
                           typo[:-1])

    def compute_id_and_rel_entropy_for_single_typo(self, typo, t_h_id, sk):
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
        pw, pw_ent = self.get_org_pw(t_h_id, sk)
        salt_ctx = self.get_glob_hmac_salt_ctx()
        typo_id = compute_id(typo.encode('utf-8'),{t_h_id:sk}, salt_ctx)
        typo_ent = self.get_entropy_stat(typo)
        rel_ent = typo_ent - pw_ent
        logger.debug("computed typo id:{}, and relative entropy:{}".format(
            typo_id,rel_ent))
        return typo_id, rel_ent
    
    def fetch_from_cache(self, typo, increaseCount=True, updateLog = True):
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
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("Searching for typo in {}".format(hashCacheT))
        ts = self.get_time_str()
        db = self.getDB()
        cachT = db[hashCacheT]
        for CachLine in cachT:
            sa = binascii.a2b_base64(CachLine['salt'])
            hs_bytes, sk = derive_secret_key(typo, sa)
            t_h_id = CachLine['H_typo'] # the hash id is in base64 form
            hsInTable = binascii.a2b_base64(t_h_id) #maybe better to encdode the other? TODO

            # we removed the typo_id from the hashCache for security reasons
            # so it (as well as the difference in entropy) needs to be 
            # calculated every time - only if it is actually found
            
            if hsInTable == hs_bytes:
                logger.debug("Typo found in {}".format(hashCacheT))
                editDist = CachLine['edit_dist']
                isInTop5 = CachLine['top_5_fixes']
                typo_count = CachLine['count']
                typo_id, rel_typo_str = self.compute_id_and_rel_entropy_for_single_typo(typo, t_h_id, sk)
                # update table with new count
                if increaseCount:
                    logger.debug("Typo's count had been increased")
                    typo_count += 1
                    cachT.update(dict(H_typo = t_h_id, count = typo_count),['H_typo'])
                if updateLog:
                    self.update_log(ts, typo_id, editDist, rel_typo_str, isInTop5,'True', str(self.isON))
                return sk, t_h_id, True
        logger.debug("Typo wasn't found in {}".format(hashCacheT))
        return '','', False

    def update_log(self, ts, typoID_or_msg, editDist, 
                   rel_typo_ent_str, isInTop5, isInHash, allowedLogin):
        log_t = self.getDB()[logT]
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
        self.update_log(ts, ORG_PW,'0','0','False','False','True')
                                  
    def log_end_of_session(self):
        ts = self.get_time_str()
        self.getDB()[logT].insert(dict(t_id=END_OF_SESS, timestamp=ts))

    def log_message(self, msg):
        ts = self.get_time_str()
        self.getDB()[logT].insert(dict(t_id=msg, timestamp=ts))
        
    def get_approved_pk_dict(self):
        '''
        Returns a dict of pw'->pk
        for all approved typos and the original pw

        for the typos, the ids are the base64 of their hashes in HashCache
        '''
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("Getting approved pk dictionary")
        db = self.getDB()
        cachT = db[hashCacheT]
        dic = {}
        
        # all approved typos' pk
        logger.debug("Getting from {}".format(hashCacheT)) 
        for cachLine in cachT:
            typo_h_id = cachLine['H_typo'].encode('utf-8') # TODO remove encoding?
            # the typos' id for the purpose of pk_dict
            # are the base64 of their hashes
            typo_pk = cachLine['pk']
            logger.debug("Got {}'s pk:{}".format(typo_h_id,typo_pk))
            # pk is a string so can be stored as is in the table as is
            dic[typo_h_id] = typo_pk
        
        # original pw's pk
        logger.debug("Getting from {}".format(auxT))
        info_t = db[auxT]
        pw_info = info_t.find(desc=ORG_PW)
        count = 0
        for line in pw_info:
            # pw_pk = binascii.a2b_base64(line['pk'])
            pw_pk = line['pk']
            logger.debug("Got {}'s pk:{}".format(ORG_PW,pw_pk))
            dic[ORG_PW] = pw_pk
            count += 1

        if count != 1:
            raise ValueError("{} pws in aux table, instead of 1".format(count))
        logger.debug("The pk dictionary was drawn successfully")
        return dic

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
        info_ctx = binascii.b2a_base64(encrypt(pk_dict,
                                               plainInfo))
        logger.debug("Typo encrypted successfully")
        logger.debug("{}".format(info_ctx)) # TODO - yes/no?
        
        db = self.getDB()
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
        sk_dic = {t_id:t_sk}
        for line in self.getDB()[waitlistT].all():
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

    def get_top_N_typos_within_editdistance(self, typoDic, pw, pw_entropy,
                                            t_id, t_sk,
                                            updateLog = True):
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
        dataLine_editDist = self.getDB()[auxT].find_one(desc = EditCutoff)
        if dataLine_editDist == None:
            raise Exception("Edit Dist hadn't been set")
        maxEditDist = int(dataLine_editDist['data'])
        glob_salt_ctx = self.get_glob_hmac_salt_ctx()
        typo_list = []

        for typo in typoDic.keys():
            ts_list, t_hs_bs64, typo_pk, t_sa_bs64, typo_ent  = typoDic[typo]
            count = len(ts_list)
            editDist = distance(unicode(pw), unicode(typo))
            typo_id = compute_id(typo.encode('utf-8'), {t_id:t_sk}, glob_salt_ctx) #TODO
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
        return self.getDB()[tableName].count()

    def get_hash_cache_size(self):
        return self.get_table_size(hashCacheT)

    # might not be used...
    def pw_and_glob_salt_have_been_initialized(self):
        tt = self.getDB()[auxT]
        count_pw = tt.count(desc=ORG_PW)
        count_salt = tt.count(desc = GLOB_SALT)
        if count_pw == 0 and count_res == 0:
            return False
        if count_pw == 1 and count_res == 1:
            return True
        raise ValueError("There are {} instants of pw\n".format(count_pw)+
                         "And {} instants of glob_salt\n".format(count_salt)+
                         "instead of 1, 1 - in {}".format(auxT))

    def get_pw_pk_salt(self):
        pk_salt_base64 =  self.getDB()[auxT].find_one(desc=ORG_PW)
        assert pk_salt_base64, \
            "pk_salt_base64={!r}. It should not be None.".format(pk_salt_base64)
        return binascii.a2b_base64(pk_salt_base64['pk_salt'])

    def get_org_pw(self, t_h_id, t_sk):
        '''
        Returns pw, pw's entropy (in bits)
        Mainly used after the user submitted an approved typo,
        and now we need to original pw to calc edit_dist
        and the difference in entropy
        '''
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("Getting original pw")
        pwLine = self.getDB()[auxT].find_one(desc=ORG_PW)
        # ctx is in base64, so we need to decode it
        pw_ctx = binascii.a2b_base64(pwLine['ctx'])
        jsn_str = decrypt({t_h_id: t_sk}, pw_ctx)
        pw_json = json.loads(jsn_str)
        logger.debug("Fetched original password successfully")
        return pw_json['pw'], pw_json['entropy']

    def get_glob_hmac_salt_ctx(self):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.debug("Getting globl hmac salt")
        saltLine = self.getDB()[auxT].find_one(desc = GLOB_SALT)
        salt_ctx = binascii.a2b_base64(saltLine['ctx'])
        logger.debug("Fetched global salt successfully")
        return salt_ctx

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
        hashT = self.getDB()[hashCacheT]
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
        db = self.getDB()
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
        # because cachHash hash Changed
        self.update_aux_ctx(t_h_id, t_sk)

    def update_aux_ctx(self, t_h_id, t_sk):
        """
        Assumes that the auxT is ok with both password and global salt
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Updating aux ctx")
        infoT = self.getDB()[auxT]
        pwCtx = binascii.a2b_base64(infoT.find_one(desc=ORG_PW)['ctx'])
        globSaltCtx = binascii.a2b_base64(infoT.find_one(desc=GLOB_SALT)['ctx'])
        pk_dict = self.get_approved_pk_dict()
        pk_dict2 = deepcopy(pk_dict) # or we could just recall 'get_approved_pk_dict'
        # the reason for the double copy is that encrypt changes the given dict

        sk_dict = {t_h_id:t_sk}
        newPwCtx = binascii.b2a_base64(update_ctx(pk_dict, sk_dict, pwCtx))
        newGlobSaltCtx = binascii.b2a_base64(update_ctx(pk_dict2,
                                                        sk_dict, globSaltCtx))
        infoT.update(dict(desc=ORG_PW, ctx=newPwCtx),['desc'])
        infoT.update(dict(desc=GLOB_SALT, ctx=newGlobSaltCtx),['desc'])

        logger.debug("Aux ctx updated successfully")
        
        
    def clear_waitlist(self):
        self.getDB()[waitlistT].delete()
        # logger.info("{} had been deleted".format(waitlistT))
        logging.getLogger(LOGGER_NAME).info("{} had been deleted".format(waitlistT))

    def original_password_entered(self, pw, updateLog = True):
        if updateLog:
            self.log_orig_pw_use()
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Original password had been entered by user")
        pw_salt = self.get_pw_pk_salt()
        logger.debug("Deriving secret key of the password")
        _, pw_sk = derive_secret_key(pw, pw_salt)
        self.update_hash_cache_by_waitlist(ORG_PW, pw_sk, updateLog)
        
        
    def update_hash_cache_by_waitlist(self, t_h_id, t_sk, updateLog = True):
        """
        Updates the hash cache according to waitlist.
        It also updates the log accordingly (if updateLog is set)
        and clears waitlist

        @updateLog (bool) : whether to update in the log, set to True
        """
        # logger = logging.getLogger(LOGGER_NAME)
        logger.info("Updating {} by {}".format(hashCacheT,waitlistT))
        waitlistTypoDict = self.decrypt_waitlist(t_h_id, t_sk)
        orig_pw, pw_entropy = self.get_org_pw(t_h_id, t_sk)
        topNList = self.get_top_N_typos_within_editdistance(waitlistTypoDict,
                                                            orig_pw, pw_entropy,
                                                            t_h_id, t_sk,
                                                            updateLog)
        self.add_top_N_typo_list_to_hash_cache(topNList, t_h_id, t_sk)
        self.clear_waitlist()

