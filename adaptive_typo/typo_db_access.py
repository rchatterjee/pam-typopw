import dataset
import sys # TODO DELETE
from time import time
from json import dumps, loads
import os
from copy import deepcopy
from zxcvbn import password_strength
from pwd import getpwnam
from pw_pkcrypto import encrypt,decrypt,derive_public_key,\
     derive_secret_key,update_ctx,compute_id

# TODO - check whether we should switch somewhere to "hash_pw"
# TOTO - the same with "match_hashes - ot make it faster

import binascii
# from Levenshtein import distance # WILL CHANGE to kb distance
from word2keypress import distance
from random import random # maybe something else?


DB_NAME = "typoToler"
ORG_PWD = 'org_pwd'       # original password's t_id
GLOB_SALT = 'glob_salt'   # global salt's t_id
END_OF_SESS = 'END OF SESSION' # for log's use

# Tables' names:
logT = 'Log'
# table cols:   timestamp, t_id, edit_dist, top_5_fixes,
#               is_in_hash, allowed_login, rel_bit_str
hashCachT = 'HashCache'
# table cols: H_typo, salt, count, pk, t_id ,top_5_fixes, rel_bit_str'
# 

waitlistT = 'Waitlist'
# table col: base64(enc(json(typo,ts,hash,salt,entropy)))'
auxT = 'AuxSysData' # holds system's setting as well as glob_salt and enc(pwd)
# table cols: desc, data
#             pk, pk_salt, ctx
# TODO - maybe we should have the ctx data in 'data'

# auxiley info 'desc's:
AllowedTypoLogin = "AllowedTypoLogin"
InstallDate = "InstallDate"
# LastPwdChange = "LastPwdChange"       # not yet implemented
# PwdTypoPolicy = "PwdTypoPolicy"       # not yet implemented
CachSize = "CacheSize"
# PwdAcceptPolicy = "PwdAcceptPolicy"   # not yet implemented
EditCutoff = "EditCutoff"        # The edit from which (included) it's too far

#log col:
rel_bit_strength = 'rel_bit_str'

# GENERAL TODO:
# - improve computation speed
# - decide when and whether to check there were no double entries is auxT (pwd&globSalt)
# note to self -    if the original pwd is given,
#                   it needs to be updated to log independently
#                   the def logging in the functions won't do it


class UserTypoDB:
    DB_obj = None
    
    def __str__(self):
        return "UserTypoDB ({})".format(self.user)

    def __init__(self,user):
        self.user = user
        info_t = self.getDB()[auxT]
        dataLineN = info_t.find_one(desc = CachSize)
        if dataLineN != None:
            print "N already in DB" # TODO REMOVE
            self.N = int(dataLineN['data'])
        dataLine_IsON = info_t.find_one(desc = AllowedTypoLogin)
        if dataLine_IsON != None:
            self.isON = bool(dataLine_IsON['data'])
        
        
    def getDB(self):
        """
        Returns the db
        If the db hasn't been connected yet - it connects to it
        """
        if self.DB_obj == None:
            self.DB_obj = dataset.connect("sqlite:////home/{}/{}.db"\
                               .format(self.user,DB_NAME))
        return self.DB_obj
    
    def get_DB_path(self):
        return "/home/{}/{}.db".format(self.user,DB_NAME)
    
    def is_typotoler_init(self):
        return self.is_aux_init()

    def disallow_login(self):
        if not is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self.getDB()[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin,data="False"),['desc'])
        self.isON = False

    def allow_login(self):
        if not is_typotoler_init():
            raise Exception("Typotoler DB wasn't initiated yet!")
        sys_aux_T = self.getDB()[auxT]
        sys_aux_T.update(dict(desc=AllowedTypoLogin,data="True"),['desc'])
        self.isON = True
        
    
    def is_aux_init(self):
        infoT = self.getDB()[auxT]
        encPwd = infoT.find_one(desc=ORG_PWD)
        globSalt = infoT.find_one(desc=GLOB_SALT)
        if (globSalt == None) != (encPwd == None):
            # if glob and pwd aren't in the same initialization state
            raise Exception("{} is corrupted!".format(auxT))
        return encPwd != None

    def init_typotoler(self,pwd,N):
        """
        Initiate the typotolers.
        Makes sure that the DB has the right permissions,
        and Initiate the tables, as well as hashCache size, the global salt
        and so on.
        """
        username = self.user
        u_data = getpwnam(username)
        u_id = u_data[2]
        g_id = u_data[3]
        db_path = self.get_DB_path()
        os.chown(db_path,u_id,g_id)     # change owner to user
        os.chmod(db_path,0600)          # rw only for owner
        
        self.init_tables(pwd,N)
        
    def init_tables(self,pwd,N,maxEditDist = 1,typoTolerOn = True):
        """
        Initiate the tables of the db, most importantly - the aux-info
        @N (int): the max size of HashCache, based on max computation time
        @pwd (string): the user's main/original password
        """
        db = self.getDB()
        # db[logT].delete()       # we can probably remove it
        # db[waitlistT].delete()  # we can probably remove it
        # db[hashCachT].delete()  # we can probably remove it
        db[auxT].delete()         # make sure there's no old unrelevant data
        self.init_aux_data(N,typoTolerOn,maxEditDist)
        self._insert_first_password_and_global_salt(pwd)

    def init_aux_data(self,N,typoTolerOn = True,maxEditDist=1):
        db = self.getDB()
        info_t = db[auxT]
        if info_t.find_one(desc = AllowedTypoLogin) != None:
            raise Exception("Initial aux data have already been inserted")
        info_t.insert(dict(desc=CachSize,data=str(N)))
        self.N = N # in the future might be dynamic and drawn from table at need TODO
        info_t.insert(dict(desc=AllowedTypoLogin,data=str(typoTolerOn)))
        self.isON = typoTolerOn
        info_t.insert(dict(desc=EditCutoff,data=str(maxEditDist)))
        
        
        
    def is_typotoler_on(self):
        dataLine = self.getDB()[auxT].find_one(desc=AllowedTypoLogin)
        if dataLine == None: # for example, after install if user enters a typo
            return False
        return bool(dataLine['data'])
        
    def is_in_top_5_fixes(self,orig_pwd,typo):
        if typo.capitalize() == orig_pwd:
            return True
        if typo.swapcase() == orig_pwd:
            return True
        if typo.lower() == orig_pwd:
            return True
        if typo.upper() == orig_pwd:
            return True
        if typo[1:] == orig_pwd:
            return True
        if typo[:-1] == orig_pwd:
            return True
        return False

    def compute_id_and_rel_entropy_for_single_typo(self,typo,t_h_id,sk):
        """
        Calculates the typo_id and relative entropy.
        since if does the whole process of fetching needed information
        in case of multiple computations, it'd be better NOT to use this
        function

        @typo (string) : the typo
        @t_h_id (hex string): the hash of the typo, serves as id for sk dict
        @sk (ECC key) : the secret key of the typo
        """
        pw,pw_ent = self.get_org_pwd(t_h_id,sk)
        salt_ctx = self.get_glob_hmac_salt_ctx()
        print "pw:{}, sk:{}".format(pw,str(sk))
        typo_id = compute_id(typo.encode('utf-8'),{t_h_id:sk},salt_ctx)
        typo_ent = self.get_entropy_stat(typo)
        rel_ent = typo_ent - pw_ent
        return typo_id,rel_ent
    
    def fetch_from_cache(self,typo,increaseCount=True,updateLog = True):
        '''
        Returns typo's pk, typo's HASH ID, True if it's in HashCach
        If not - return "","",False
        By default:
            - increase the typo count
            - write the relevant log    
        @typo (string) : the given password typo
        @increaseCount (bool) : whether to update the typo's count if found
        @updateLog (bool) : whether to insert an update to the log
        ''' 
        ts = self.get_time_str()
        db = self.getDB()
        cachT = db[hashCachT]
        for CachLine in cachT:
            sa = binascii.a2b_base64(CachLine['salt'])
            hs_bytes,sk = derive_secret_key(typo,sa)
            t_h_id = CachLine['H_typo'] # the hash id is in base64 form
            hsInTable = binascii.a2b_base64(t_h_id) #maybe better to encdode the other? TODO

            # typo_id = CachLine['t_id'] TODO REMOVE
            # we removed the typo_id from the hashCache for security reasons
            # so it (as well as the difference in entropy) needs to be calculated
            # will be calculated only if found
            
            editDist = CachLine['edit_dist']
            # TODO isInTop5
            isInTop5 = CachLine['top_5_fixes']
            typo_count = CachLine['count']
            
            if hsInTable == hs_bytes:
                typo_id,rel_typo_str = self.compute_id_and_rel_entropy_for_single_typo(typo,t_h_id,sk)
                # update table with new count
                if increaseCount:
                    typo_count += 1
                    cachT.update(dict(H_typo = t_h_id,count = typo_count),['H_typo'])
                if updateLog:
                    self.update_log(ts,typo_id,editDist,rel_typo_str,isInTop5,'True',str(self.isON))
                print "in hash cache!" # TODO REMOVE
                
                return sk,t_h_id,True

        return '','',False

    def update_log(self,ts,typoID_or_msg,editDist,rel_typo_ent_str,isInTop5,isInHash,allowedLogin):
        log_t = self.getDB()[logT]
        log_t.insert(dict(t_id=typoID_or_msg, timestamp=ts, edit_dist=editDist,
                          top_5_fixes=isInTop5, is_in_hash=isInHash,
                          allowed_login=allowedLogin,
                          rel_typo_str=rel_typo_ent_str))
                    
    def log_orig_pwd_use(self):
        ts = self.get_time_str()
        self.update_log(ts,ORG_PWD,'0','0','False','False','True')
                                  
    def log_end_of_session(self):
        ts = self.get_time_str()
        self.getDB()[logT].insert(dict(t_id=END_OF_SESS,timestamp=ts))
        
    def get_approved_pk_dict(self):
        '''
        Returns a dict of pw'->pk
        for all approved typos and the original pwd

        for the typos, the ids are the base64 of their hashes in HashCache
        '''
        db = self.getDB()
        cachT = db[hashCachT]
        dic = {}

        # all approved typos' pk
        for cachLine in cachT:
            typo_h_id = cachLine['H_typo']
            # the typos' id for the purpose of pk_dict
            # are the base64 of their hashes
            #typo_pk = binascii.a2b_base64(cachLine['pk'])
            typo_pk = cachLine['pk']
            # remember - pk is a string so can be stored as is in the table
            dic[typo_h_id] = typo_pk

        
        # original pwd's pk
        info_t = db[auxT]
        pwd_info = info_t.find(desc=ORG_PWD)
        count = 0
        for line in pwd_info:
            # pwd_pk = binascii.a2b_base64(line['pk'])
            pwd_pk = line['pk']
            dic[ORG_PWD] = pwd_pk
            count += 1

        if count != 1:
            raise ValueError("{} pwds in aux table, instead of 1".format(count))

        return dic

    def get_time_str(self):
        """
        Returns the timestamp in a string, in a consistent format
        which works in linux and can be stored in the DB
        (unlike datetime.datetime, for example)
        """
        return str(time())

    def get_entropy_stat(self,typo):
        return password_strength(typo)['entropy']
    
    def add_typo_to_waitlist(self,typo):
        """
        Adds the typo to the waitlist.
        saves the timestamp as well (for logging reasons)
        **** for now: (might be change from computation time reasons) ****
        computes an hash for the typo (+sa)
        encryptes everything in a json format
        enc(json(dict(...)))
        dictionary keys: typo_hs,typo_pk,typo_pk_salt,timestamp,typo

        @typo (string) : the user's passwrod typo
        """
        # should ts be encrypted as well?
        sa = os.urandom(16)
        typo_hs, typo_pk = derive_public_key(typo,sa)
        hs_b64 = binascii.b2a_base64(typo_hs)
        #pk_b64 = binascii.b2a_base64(typo_pk)
        sa_b64 = binascii.b2a_base64(sa)

        ts = self.get_time_str()
        typo_str = self.get_entropy_stat(typo)
        plainInfo = dumps({"typo_hs":hs_b64,"typo_pk":typo_pk, #
                                "typo_pk_salt":sa_b64,
                                "timestamp":ts,"typo":typo,
                                'typo_ent_str':typo_str})
        info_ctx = binascii.b2a_base64(encrypt(self.get_approved_pk_dict(),
                                               plainInfo))
        db = self.getDB()
        w_list_T = db[waitlistT]

        w_list_T.insert(dict(ctx = info_ctx))

    def decrypt_waitlist(self, t_id,t_sk):
        '''
        Returns a dictionary of the typos in waitlist, unsorted,
        Key = typo (string)
        Value = (typo,t_count,ts_list,typo_hs,t_pk,t_pk_salt)
        '''
        new_typo_dic = {}
        sk_dic = {t_id:t_sk}
        for line in self.getDB()[waitlistT].all():
            bin_ctx = binascii.a2b_base64(line['ctx'])
            typo_info = loads(decrypt(sk_dic,bin_ctx))
            ts = typo_info['timestamp']
            typo = typo_info['typo']
            #typo_hs = binascii.a2b_base64(typo_info['typo_hs'])
            typo_hs_b64 = typo_info['typo_hs']
            t_pk = typo_info['typo_pk'] #
            typo_str = typo_info['typo_ent_str']
            typo_pk_salt = binascii.a2b_base64(typo_info["typo_pk_salt"])
            if typo not in new_typo_dic:
                new_typo_dic[typo] = ([ts],typo_hs_b64,t_pk,
                                      typo_pk_salt,typo_str)
            else:
                # TODO DELETE
                #_, t_count, ts_list,_,_,_,_ = new_typo_dic[typo]
                #ts_list.append(ts)
                #t_count += 1
                #new_typo_dic[typo]=(typo,t_count,ts_list,
                #                    typo_hs,t_pk,typo_pk_salt,typo_str)
                new_typo_dic[typo][0].append(ts) # appending ts to ts_list

        return new_typo_dic

    def get_top_N_typos_within_editdistance(self, typoDic, pwd, pwd_entropy,
                                            t_id, t_sk,
                                            updateLog = True):
        """
        Gets a dictionary (from waitlist) of all new typos
        calculates their editDistance (in the future isTop5 TODO )
        and returns the top N among them, within the edit distance

        by defaults - update the log retroactively on each entered typo

        @typoDic (dict) - a dictinary of all typos. see "decrypt_waitlist"
                            for foramt
        @pwd (string) - the original password
        @t_id, t_sk - an approved typo id and it's sk
        @updateLog (bool) : whether to update the log about each typo
        """
        dataLine_editDist = self.getDB()[auxT].find_one(desc = EditCutoff)
        if dataLine_editDist == None:
            raise Exception("Edit Dist hadn't been set")
        maxEditDist = int(dataLine_editDist['data'])
        glob_salt_ctx = self.get_glob_hmac_salt_ctx()
        typo_list = []

        for typo in typoDic.keys():
            #ts_list,typo_hs,typo_pk,typo_pk_salt,typo_ent  = typoDic[typo]
            ts_list,t_hs_bs64,typo_pk,typo_pk_salt,typo_ent  = typoDic[typo]
            count = len(ts_list)
            #t_hs_bs64 = binascii.b2a_base64(typo_hs) # we decode and encode for no reason
            
            
            t_sa_bs64 = binascii.b2a_base64(typo_pk_salt)
            editDist = distance(unicode(pwd), unicode(typo)) # WILL CHANGE to pressDist TODO
            typo_id = compute_id(typo.encode('utf-8'),{t_id:t_sk},glob_salt_ctx) #TODO
            isTop5Fixes = str(self.is_in_top_5_fixes(pwd,typo))
            rel_typo_str = typo_ent - pwd_entropy ###
            # will add it to the information inserted in the list append

            # writing into log for each ts
            if updateLog:
                for ts in ts_list:
                    # if typo got into waitlist - it's not in cach
                    # and not allowed login
                    self.update_log(ts,typo_id,editDist,rel_typo_str,
                                    isTop5Fixes,'False','False')

            closeEdit = editDist <= maxEditDist
            notMuchWeaker = rel_typo_str >= -3 # TODO change to be 3 from aux
            notTooWeak = typo_ent >= 16        # TODO change to be 16 from aux
            # and to be "True" if not found in aux
            
            if  closeEdit and notMuchWeaker and notTooWeak: # TODO CHANGE !
                typo_dic_obj = {'H_typo':t_hs_bs64,'salt':t_sa_bs64,
                                'count':count,'pk':typo_pk,
                                'edit_dist':editDist,
                                'top_5_fixes':isTop5Fixes} #'t_id':typo_id, removing t_id from hashCache TODO
                typo_list.append(typo_dic_obj)
            else:
                print "{} not entered because editDist {}".format(typo_id,
                                                                  editDist)
                print " or because rel_typo_str is {}".format(rel_typo_str)

        return sorted(typo_list,key = lambda x:x['count'],reverse=True)[:self.N]

    #tmp TODO DELETE
    def printAllWaitlist(self):
        db = self.getDB()
        w_list_T = db[waitlistT]
        for line in w_list_T.all():
            print line

    #tmp TODO DELETE
    def printCachHash(self):
        print " ^^^^^^^^^ PRINTING HASH CACHE ^^^^^^^^^^ "
        db = self.getDB()
        cachT = db[hashCachT]
        print cachT.columns
        for line in cachT:
            print line

        print " ^^^^^^^^^ END OF PRINTING HASH CACHE ^^^^^^^^^^ "

    def get_table_size(self,tableName):
        return self.getDB()[tableName].count()

    def get_hash_cach_size(self):
        return self.get_table_size(hashCachT)

    # might not be used...
    def pwd_and_glob_salt_have_been_initialized(self):
        tt = self.getDB()[auxT]
        count_pwd = tt.count(desc = ORG_PWD)
        count_salt = tt.count(desc = GLOB_SALT)
        if count_pwd == 0 and count_res == 0:
            return False
        if count_pwd == 1 and count_res == 1:
            return True
        raise ValueError("There are {} instants of pwd\n".format(count_pwd)+
                         "And {} instants of glob_salt\n".format(count_salt)+
                         "instead of 1,1 - in {}".format(auxT))

    def get_pwd_pk_salt(self):
        pk_salt_base64 =  self.getDB()[auxT].find_one(desc = ORG_PWD)['pk_salt']
        return binascii.a2b_base64(pk_salt_base64)

    def get_org_pwd(self,t_h_id,t_sk):
        '''
        Returns pwd,pwd's entropy (in bits)
        Mainly used after the user submitted an approved typo,
        and now we need to original pwd to calc edit_dist
        and the difference in entropy
        '''
        pwdLine = self.getDB()[auxT].find_one(desc = ORG_PWD)
        # ctx is in base64, so we need to decode it
        pwd_ctx = binascii.a2b_base64(pwdLine['ctx'])
        jsn_str = decrypt({t_h_id:t_sk},pwd_ctx)
        pwd_json = loads(jsn_str)
        return pwd_json['pwd'],pwd_json['entropy']

    def get_glob_hmac_salt_ctx(self):
        """
        Returns the global salt ctx used for computing ID for each typo
        """
        saltLine = self.getDB()[auxT].find_one(desc = GLOB_SALT)
        salt_ctx = binascii.a2b_base64(saltLine['ctx'])
        return salt_ctx

    # WILL CHANGE
    def cach_insert_policy(self,old_t_c,new_t_c):
        # TODO
        chance = float(new_t_c)/(int(old_t_c)+1)
        print "the chance is:{}".format(chance) #TODO REMOVE
        rnd = random()
        print "rnd is:{}".format(rnd) # TODO REMOVE
        return rnd <= chance

    def get_lowest_M_line_in_hash_cach(self,M):
        # might be slow - and than we should re-write it
        hashT = self.getDB()[hashCachT]
        result = hashT.find(order_by='count',_limit=M)
        return result


    def add_top_N_typo_list_to_hash_cach(self,typo_list,t_h_id,t_sk):
        # TODO - make sure that i updates the way it should
        '''
        updates the hashCachTable according to the update scheme
        @typo_list (list of dict): a list of dictionary, each dictionary is a
        a row of the typo, with all relevent fields
        '''
        # right now it uses certain scheme, we should change it later on

        # adding if there's free space
        hash_cach_size = self.get_hash_cach_size()
        new_typos = len(typo_list)
        emptyPlaces = self.N - hash_cach_size
        addNum = min(emptyPlaces,new_typos)
        print "N:{}, ADD_NUM: {} ,cachSize: {}, new typos: {}, empty: {}".format(
            self.N,addNum,hash_cach_size,new_typos,emptyPlaces) # TODO REMOVE
        
        #if addNum > 0:
        nextLines = self.get_lowest_M_line_in_hash_cach(new_typos - addNum)
        db = self.getDB()
        hashT = db[hashCachT]
        if emptyPlaces > 0:
            hashT.insert_many(typo_list[:addNum]) # TODO
            # for typo_d in typo_list[:addNum]:
            #    hashT.insert(typo_d)

        # need to decide what to do with the rest
        # checking whether the rest are added
        for typoDict in typo_list[addNum:]:
            oldLine = next(nextLines)
            if self.cach_insert_policy(oldLine['count'],typoDict['count']):
                typoDict['count'] = oldLine['count'] + 1 #
                hashT.delete(H_typo = oldLine['H_typo']) # maybe use update instead TODO
                hashT.insert(typoDict)     # later on maybe use add_many to fasten TODO

        # update the ctx of the original password and the global salt
        # because cachHash hash Changed
        self.update_aux_ctx(t_h_id,t_sk)

    def update_aux_ctx(self,t_h_id,t_sk):
        """
        Assumes that the auxT is ok with both password and global salt
        """
        print "updating aux ctx"
        infoT = self.getDB()[auxT]
        pwdCtx = binascii.a2b_base64(infoT.find_one(desc=ORG_PWD)['ctx'])
        globSaltCtx = binascii.a2b_base64(infoT.find_one(desc=GLOB_SALT)['ctx'])
        pk_dict = self.get_approved_pk_dict()
        pk_dict2 = deepcopy(pk_dict) # or we could just recall 'get_approved_pk_dict'
        # the reason for the double copy is that encrypt changes the given dict

        for key in pk_dict.keys():
            print "k:{},v:{}".format(key, str(pk_dict[key]))
        #print "FIRST PRINT" #TODO REMOVE
        #for t_id in pk_dict: # TODO REMOVE
        #    print "updated aux for {}:{}".format(t_id,pk_dict[t_id])
        sk_dict = {t_h_id:t_sk}
        newPwdCtx = binascii.b2a_base64(update_ctx(pk_dict,sk_dict,pwdCtx))
        newGlobSaltCtx = binascii.b2a_base64(update_ctx(pk_dict2,
                                                        sk_dict,globSaltCtx))
        infoT.update(dict(desc=ORG_PWD,ctx=newPwdCtx),['desc'])
        infoT.update(dict(desc=GLOB_SALT,ctx=newGlobSaltCtx),['desc'])

        #print "SECOND PRINT" # TODO REMOVE
        #for t_id in pk_dict: # TODO REMOVE
        #    print "updated aux for {}:{}".format(t_id,pk_dict[t_id])
        
        
        
    def clear_waitlist(self):
        self.getDB()[waitlistT].delete()

    def original_password_entered(self,pwd,updateLog = True):
        if updateLog:
            self.log_orig_pwd_use()
        pwd_salt = self.get_pwd_pk_salt()
        _,pwd_sk = derive_secret_key(pwd,pwd_salt)
        self.update_hash_cach_by_waitlist(ORG_PWD,pwd_sk,updateLog)
        
        
    def update_hash_cach_by_waitlist(self,t_h_id,t_sk,updateLog = True):
        """
        Updates the hash cache according to waitlist.
        It also updates the log accordingly (if updateLog is set)
        and clears waitlist

        @updateLog (bool) : whether to update in the log, set to True
        """
        # we might want to avoid saving those obj.. or some other comp. improv.
        waitlistTypoDict = self.decrypt_waitlist(t_h_id,t_sk)
        orig_pwd,pwd_entropy = self.get_org_pwd(t_h_id,t_sk)
        topNList = self.get_top_N_typos_within_editdistance(waitlistTypoDict,
                                                            orig_pwd,pwd_entropy,
                                                            t_h_id, t_sk,
                                                            updateLog)
        self.add_top_N_typo_list_to_hash_cach(topNList,t_h_id,t_sk)
        self.clear_waitlist()
        
        
    def _insert_first_password_and_global_salt (self, pw):
        # TODO - insert log entry of initiation
        db = self.getDB()
        info_t = db[auxT]
        pwd_already_init = info_t.find_one(desc=ORG_PWD) != None
        if pwd_already_init:
            raise Exception("Original password is already stored")
        
        pwd_salt_pk = os.urandom(16)

        pw_hash,pw_pk = derive_public_key(pw,pwd_salt_pk)
        #_,pw_sk = derive_secret_key(pw,salt_pk)

        glob_salt_hmac = os.urandom(16)
        self.glob_salt_tmp = glob_salt_hmac # TODO REMOVE

        pwd_salt_base64 = binascii.b2a_base64(pwd_salt_pk)

        pw_entropy = self.get_entropy_stat(pw) ###
        pwd_json = dumps({'pwd':pw,'entropy':pw_entropy})
        # typo_plaintxt = json.dump({'desc':'pwd','data':pw,'pk':pw_pk,'sa':salt_pk})
        # salt_plaintxt = json.dump({'desc':'salt','data':salt_pk})

        # tas the pk needs to be available it's a bit redundant
        # might change

        pk_dict = {ORG_PWD:pw_pk}
        pw_json_cipher = binascii.b2a_base64(encrypt(pk_dict,pwd_json))
        # leakes somewhat the size of the pwd
        glob_salt_cipher = binascii.b2a_base64(encrypt(pk_dict,glob_salt_hmac))

        # TODO - change it to be 'data' instead of 'ctx'
        info_t.insert(dict(ctx=pw_json_cipher,pk=pw_pk,pk_salt = pwd_salt_base64,
                           desc=ORG_PWD))
        info_t.insert(dict(ctx=glob_salt_cipher,desc=GLOB_SALT))

        return




def main():
    '''
    first argument is the username
    '''
    args = argv[1:]
    for r in args:
        print str(r)

    user = args[0]
    myDB = UserTypoDB(user)
    DB = myDB.getDB()
    myDB.clear_waitlist()
    pwd = 'dlue'
    print " $$$$$$$$$ IS INIT $$$$$$$$$$$$"
    print str(myDB.is_aux_init())
    myDB.init_tables(pwd,3)
    print " $$$$$$$$$ IS INIT $$$$$$$$$$$$"
    print (myDB.is_aux_init())

    pwd_pk_salt = myDB.get_pwd_pk_salt()
    print "pwd_pk_salt: {}".format(pwd_pk_salt)
    _,pwd_sk = derive_secret_key(pwd,pwd_pk_salt)
    getPwd = myDB.get_org_pwd(ORG_PWD,pwd_sk)
    print "{} is the pwd we got".format(getPwd)
    print "{} is org pwd".format(pwd)
    '''
    glob_salt_ctx = myDB.get_glob_hmac_salt_ctx()
    check_glob_salt = decrypt({ORG_PWD:pwd_sk},glob_salt_ctx)
    print "real glob salt: {}".format(myDB.glob_salt_tmp)
    print "decrypted glob salt: {}".format(check_glob_salt)
    '''

    myDB.add_typo_to_waitlist("dlUE")
    myDB.add_typo_to_waitlist("dlUE")
    myDB.add_typo_to_waitlist("dlUE")
    myDB.add_typo_to_waitlist("dlUE")
    myDB.add_typo_to_waitlist("dlUE")
    myDB.add_typo_to_waitlist("dlUE")
    myDB.add_typo_to_waitlist("dlUE")
    
    myDB.add_typo_to_waitlist("blae")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("shoe")
    
    myDB.add_typo_to_waitlist("dlum")
    myDB.add_typo_to_waitlist("dluep")


    print myDB.get_org_pwd(ORG_PWD,pwd_sk)
    '''
    dic = myDB.decrypt_waitlist(ORG_PWD,pwd_sk)
    top_N_list = myDB.get_top_N_typos_within_editdistance(dic,pwd,ORG_PWD,pwd_sk)
    print "dic:"
    print dic
    print "top N:"
    print top_N_list

    print "#" * 34
    myDB.printCachHash()
    myDB.add_top_N_typo_list_to_hash_cach(top_N_list,ORG_PWD,pwd_sk)
    myDB.clear_waitlist()
    print "~" * 34'''
    myDB.update_hash_cach_by_waitlist(ORG_PWD,pwd_sk)
    myDB.printCachHash()
    allPks = myDB.get_approved_pk_dict()
    print "approved pk dict:"
    print allPks

    t_sk,t_id,_ = myDB.fetch_from_cache('blue',False,False)
    print "fetching pwd: {}".format(myDB.get_org_pwd(t_id,t_sk))
    


    return 0
if __name__ == '__main__':
    main()
