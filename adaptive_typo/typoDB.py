'''
################################
last update: 08/30/16
DO NOT USE
################################
'''




import dataset
import sys
import time
import json
from Crypto.Random import random
from pw_pkcrypto import *
import binascii
import editdistance # WILL CHANGE to kb distance
import random # maybe something else?
import itertools

DB_NAME = "typoToler"
logT = 'LogTable'
hashCachT = 'HashCachTable'
' col: H_typo, salt, count, pk, t_id ' # need to add isTop5
auxT = 'AuxTable'
' col: data, d_hash, pk'
# will have the ps and the global sa (for HMAM for id computation)
waitlistT = 'WaitlistTable'
' col: base64(enc(json(typo,ts,hash,salt)))'
#allData = 'allData'

ORG_PWD = 'org_pwd'
GLOB_SALT = 'glob_salt'
MAX_EDIT_DIST_INCLUDED = 1
# col: key_id,key. when key_id is the Id of the sk the decrypts the key




# the HashCach will hold the pk as well

class UserTypoDB:
    glob_salt_tmp = 'para'
    def __init__(self,user,N):
        self.user = user
        self.N = N
        
    def getDB(self): # should we hold the DB connection object as a member?
        return dataset.connect("sqlite:////home/{}/{}.db"\
                               .format(self.user,DB_NAME))

    def init_tables(self,pwd):
        db = self.getDB()
        db[logT]
        db[auxT].delete() #
        #db[allData]
        db[waitlistT].delete() #
        self._insert_first_password_and_global_salt(pwd)
        db[hashCachT].delete() #
            
        
    def is_in_cach(self,typo,increaseCount=True):
        '''
        returns the typo's pk and ID if it's in HashCach
        if not - returns an empty strings "",""
        By default: increase the typo count as well
        ''' # in python2.7 hex is a string
        db = self.getDB()
        cachT = db[hashCachT]
        for CachLine in cachT:
            sa = CachLine[salt]
            hs,sk = derive_secret_key(typo,sa)
            hsInTable = CachLine[H_typo]
            typo_id = CachLine[t_id]
            typo_count = CachLine[count]
            if hsInTable == hs:
                # update table with new count
                if increaseCount:
                    typo_count += 1
                    cachT.update(dict(t_id = typo_id,count = typo_count),['count'])

                return sk,typo_id

        return '',''

    def sort_cach(self):
        pass
        # when we sort the cach we need to reCalc the pwd encryption and reCalc the keysTable

    def get_approved_pk_dict(self):
        '''
        returns a dict of pw'->pk
        for all approved typos and the original pwd
        '''
        db = self.getDB()
        cachT = db[hashCachT]
        dic = {}
        
        # all approved typos' pk
        for cachLine in cachT:
            typo_id = cachLine[t_id]
            typo_pk = cachLine[pk]
            dic[typo_id] = typo_pk

        #print "*"*12," FINISHED TYPOS ","*"*12 # REMOVE
        # original pwd's pk
        info_t = db[auxT]                      
        #print "%" * 24                         # REMOVE
        #print info_t.columns                   # REMOVE
        pwd_info = info_t.find(desc=ORG_PWD)
        #print "^" * 24                         # REMOVE
        count = 0
        for line in pwd_info:
            pwd_pk = line['pk']
            dic[ORG_PWD] = pwd_pk
            count += 1
            
        if count != 1:
            raise ValueError("{} pwds in aux table, instead of 1".format(count))

        return dic
    
    def get_time_str(self):
        return str(time.time())
    
    def add_typo_to_waitlist(self,typo):
        # should ts be encrypted as well?
        sa = os.urandom(16)
        typo_hs, typo_pk = derive_public_key(typo,sa)
        hs_b64 = binascii.b2a_base64(typo_hs)
        pk_b64 = binascii.b2a_base64(typo_pk)
        sa_b64 = binascii.b2a_base64(sa)
        
        ts = self.get_time_str()
        plainInfo = json.dumps({"typo_hs":hs_b64,"typo_pk":pk_b64,
                                "typo_pk_salt":sa_b64,
                                "timestamp":ts,"typo":typo})
        info_ctx = binascii.b2a_base64(encrypt(self.get_approved_pk_dict(),
                                               plainInfo))

        db = self.getDB()
        w_list_T = db[waitlistT]

        w_list_T.insert(dict(ctx = info_ctx))

    def decrypt_waitlist(self, t_id,t_sk):
        '''
        returns a dictionary of the typos in waitlist
        '''
        new_typo_dic = {}
        sk_dic = {t_id:t_sk}
        for line in self.getDB()[waitlistT].all():
            bin_ctx = binascii.a2b_base64(line['ctx'])
            typo_info = json.loads(decrypt(sk_dic,bin_ctx))
            ts = typo_info['timestamp']
            typo = typo_info['typo']
            typo_hs = binascii.a2b_base64(typo_info['typo_hs'])
            typo_pk = binascii.a2b_base64(typo_info['typo_pk'])
            typo_pk_salt = binascii.a2b_base64(typo_info["typo_pk_salt"])
            if typo not in new_typo_dic:
                new_typo_dic[typo] = (typo,1,[ts],typo_hs,typo_pk,typo_pk_salt)
            else:
                _, t_count, ts_list,_,_,_ = new_typo_dic[typo]
                ts_list.append(ts)
                t_count += 1
                new_typo_dic[typo]=(typo,t_count,ts_list,
                                    typo_hs,typo_pk,typo_pk_salt)

        return new_typo_dic
                
    def get_top_N_typos_within_editdistance(self,typoDic,pwd,t_id,t_sk):
        '''
        Will also update log TODO
        '''

        ' col: H_typo, salt, count, pk, t_id '
        
        glob_salt_ctx = self.get_glob_hmac_salt_ctx()
        print "in get top N"
        print "salt ctx:"
        print glob_salt_ctx
        print "#"*24
        typo_list = []
        
        for typo in typoDic.keys():
            _, count, ts_list,typo_hs,typo_pk,typo_pk_salt = typoDic[typo]
            editDist = editdistance.eval(pwd,typo) # WILL CHANGE
            typo_id = compute_id(typo.encode('utf-8'),{t_id:t_sk},glob_salt_ctx) #TODO
            # typo_id = 'fake_id_fix_line_above:' + typo
            # calc isTop5Fixer # TODO
            # will add it to the information inserted in the list append
            # writing into log for each ts
            typo_dic_obj = {'H_typo':typo_hs,'salt':typo_pk_salt,'count':count,
                       'pk':typo_pk,'t_id':typo_id}
            if editDist <= MAX_EDIT_DIST_INCLUDED:
                typo_list.append(typo_dic_obj)

        #                                    x:x[1] = count field
        return sorted(typo_list,key = lambda x:x['count'],reverse=True)[:self.N]
            
        

    def clear_waitlist(self):
        db = self.getDB()
        w_list_T = db[waitlistT]
        w_list_T.delete()

    #tmp
    def printAllWaitlist(self):
        db = self.getDB()
        w_list_T = db[waitlistT]
        for line in w_list_T.all():
            print line
            
    #tmp    
    def printCachHash(self):
        
        db = self.getDB()
        cachT = db[hashCachT]
        print cachT.columns
        for line in cachT:
            print line

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
                         "instead of 1,1 - in auxT")

    def get_pwd_pk_salt(self):
        pk_salt_base64 =  self.getDB()[auxT].find_one(desc = ORG_PWD)['pk_salt']
        return binascii.a2b_base64(pk_salt_base64)
            
    def get_org_pwd(self,t_id,t_sk):
        '''
        Mainly used after the user submitted an approved typo,
        and now we need to original pwd to calc edit_dist
        '''
        pwdLine = self.getDB()[auxT].find_one(desc = ORG_PWD)
        # ctx is in base64, so we need to decode it
        pwd_ctx = binascii.a2b_base64(pwdLine['ctx'])
        return decrypt({t_id:t_sk},pwd_ctx)

    def get_glob_hmac_salt_ctx(self):#,t_id,t_sk): #compute_id get a saltctx
        saltLine = self.getDB()[auxT].find_one(desc = GLOB_SALT)
        salt_ctx = binascii.a2b_base64(saltLine['ctx'])
        #return decrypt({t_id:t_sk},pwd_ctx) #compute_id get a saltctx
        return salt_ctx
        
    def cach_insert_policy(self,old_t_c,new_t_c):
        # TODO
        chance = float(new_t_c)/int(old_t_c + 1)
        print "the chance is:{}".format(chance) #TODO REMOVE
        rnd = random.random()
        print "rnd is:{}".format(rnd) # TODO REMOVE
        return rnd <= chance

    def get_lowest_M_line_in_hash_cach(self,M):
        # might be slow - and than we should re-write it
        hashT = self.getDB()[hashCachT]
        result = hashT.find(order_by='count',_limit=M)
        return result
        
    
    def add_top_N_typo_list_to_hash_cach(self,typo_list):
        '''
        updates the hashCachTable according to the update scheme
        @typo_list (list of dict): a list of dictionary, each dictionary is a
        a row of the typo, with all relevent fields
        '''
        # right now it uses certain scheme, we should change it later on

        
        hashT = self.getDB()[hashCachT]
        
        hash_cach_size = self.get_hash_cach_size()
        new_typos = len(typo_list)
        emptyPlaces = self.N - hash_cach_size
        addNum = min(emptyPlaces,new_typos)
        if addNum > 0:
            nextLines = get_lowest_M_line_in_hash_cach(new_typos-addNum)
        if emptyPlaces > 0:
            hashT.insert_many(typo_list[:addNum])
        
        # need to decide what to do with the rest
        for typoDict in typo_list[addNum:]:
            oldLine = next(nextLines)
            if cach_insert_policy(oldLine['count'],typoDict['count']):
                typoDict['count'] = typoDict['count'] + 1
                hashT.delete
            
        
        
        



            
    
    def _insert_first_password_and_global_salt (self, pw):

        # *************** TODO *************
        # add some checks to gurantee its the first password
        
        pwd_salt_pk = os.urandom(16)
        
        pw_hash,pw_pk = derive_public_key(pw,pwd_salt_pk)
        #_,pw_sk = derive_secret_key(pw,salt_pk)
        
        glob_salt_hmac = os.urandom(16)
        self.glob_salt_tmp = glob_salt_hmac # TODO REMOVE

        pwd_salt_base64 = binascii.b2a_base64(pwd_salt_pk)
        
        # typo_plaintxt = json.dump({'desc':'pwd','data':pw,'pk':pw_pk,'sa':salt_pk})
        # salt_plaintxt = json.dump({'desc':'salt','data':salt_pk})
        
        # tas the pk needs to be available it's a bit redundant
        # might change
        
        pk_dict = {ORG_PWD:pw_pk}
        pw_cipher = binascii.b2a_base64(encrypt(pk_dict,pw))
        # leakes somewhat the size of the pwd
        glob_salt_cipher = binascii.b2a_base64(encrypt(pk_dict,glob_salt_hmac))

        db = self.getDB()
        info_t = db[auxT]
        info_t.insert(dict(ctx=pw_cipher,pk=pw_pk,pk_salt = pwd_salt_base64,
                           desc=ORG_PWD),types={'ctx':'blob'})
        info_t.insert(dict(ctx=glob_salt_cipher,desc=GLOB_SALT))

        return

    
        
        
        

        
        
        
            
    
        
    
            
        

def main():
    '''
    first argument is the username
    '''
    args = sys.argv[1:]
    for r in args:
        print str(r)

    user = args[0]
    myDB = UserTypoDB(user,2) # N=2
    DB = myDB.getDB()
    myDB.clear_waitlist()
    pwd = 'dlue'
    myDB.init_tables(pwd)
    
    
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
    
    
    myDB.add_typo_to_waitlist("blae")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("clue")
    myDB.add_typo_to_waitlist("shoe")

    dic = myDB.decrypt_waitlist(ORG_PWD,pwd_sk)
    top_N_list = myDB.get_top_N_typos_within_editdistance(dic,pwd,ORG_PWD,pwd_sk)   
    print "dic:"
    print dic
    print "top N:"
    print top_N_list

    # myDB.printAllWaitlist()

    
    myDB.clear_waitlist()


    return 0
if __name__ == '__main__':
    main()
    
