import dataset
import sys
import time
import json
from Crypto.Random import random
from pw_pkcrypto import *
import binascii


DB_NAME = "typoToler"
logT = 'LogTable'
hashCachT = 'HashCachTable'
' col: H_typo, salt, count, pk, t_id, '
auxT = 'AuxTable'
' col: data, d_hash, pk'
# will have the ps and the global sa (for HMAM for id computation)
waitlistT = 'WaitlistTable'
' col: base64(enc(typo)),ts
#allData = 'allData'
orgP_T = "Org_P_Table"

ORG_PWD = 'org_pwd'.encode('utf-8') 
GLOB_SALT = 'glob_salt'
# col: key_id,key. when key_id is the Id of the sk the decrypts the key

# the HashCach will hold the pk as well

class UserTypoDB:
    
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
        ts = self.get_time_str()
        typo_ctx = binascii.b2a_base64(encrypt(self.get_approved_pk_dict(),typo))

        db = self.getDB()
        w_list_T = db[waitlistT]

        w_list_T.insert(dict(ctx = typo_ctx,timestamp = ts))

    def decrypt_waitlist(self, t_id,t_sk):
        new_typo_dic = {}
        sk_dic = {t_id:t_sk}
        for line in self.getDB()[waitlistT].all():
            bin_ctx = binascii.a2b_base64(line['ctx'])
            typo = decrypt(sk_dic,bin_ctx)
            ts = line['timestamp']
            if typo not in new_typo_dic:
                new_typo_dic[typo] = (typo,1,[ts])
            else:
                _, t_count, ts_list = new_typo_dic[typo]
                ts_list.append(ts)
                t_count += 1
                new_typo_dic[typo]=(typo,t_count,ts_list)

        return new_typo_dic
                
    def get_top_legit_N_typos(self,typoDic,pwd):
        for typo in typoDic.keys():
            _, count, ts_list = typoDic[typo]
            editDist = 
        

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

    def get_glob_hmac_salt(self,t_id,t_sk):
        saltLine = self.getDB()[auxT].find_one(desc = GLOB_SALT)
        salt_ctx = binascii.a2b_base64(saltLine['ctx'])
        return decrypt({t_id:t_sk},pwd_ctx)
        
    def cach_insert_policy(self):
        return True
    
    def add_to_hash_cach(self,typo,typo_count = 1,
                         (typo_hash,typo_pk) = ("",""),typo_id = ''):
        ## ************ WORK IN PROGESSSS **************

        if typo_hash == "" or typo_pk == "":
            salt = os.urandom(16)
            typo_hash,typo_pk = derive_public_key(typo,salt)

        if cach_insert_policy():
            pass
        pass



            
    
    def _insert_first_password_and_global_salt (self, pw):

        # *************** TODO *************
        # add some checks to gurantee its the first password
        
        pwd_salt_pk = os.urandom(16)
        
        pw_hash,pw_pk = derive_public_key(pw,pwd_salt_pk)
        #_,pw_sk = derive_secret_key(pw,salt_pk)
        
        glob_salt_hmac = os.urandom(16)

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
    myDB = UserTypoDB(user)
    DB = myDB.getDB()
    myDB.clear_waitlist()
    pwd = 'pass'
    myDB.init_tables(pwd)

    pwd_pk_salt = myDB.get_pwd_pk_salt()
    print "pwd_pk_salt: {}".format(pwd_pk_salt)
    _,pwd_sk = derive_secret_key(pwd,pwd_pk_salt)
    getPwd = myDB.get_org_pwd(ORG_PWD,pwd_sk)
    print "{} is the pwd we got".format(getPwd)
    print "{} is org pwd".format(pwd)
    
    
    

    myDB.add_typo_to_waitlist("blae")
    myDB.add_typo_to_waitlist("blue")
    myDB.add_typo_to_waitlist("clue")

    myDB.printAllWaitlist()

    
    myDB.clear_waitlist()


    return 0
if __name__ == '__main__':
    main()
    
