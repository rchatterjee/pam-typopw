import dataset
import sys
import time
from Crypto.Random import random
from pw_pkcrypto import *

# will be REMOVED
'''
from Crypto.Hash import SHA3_512
from Crypto.Hash import SHA1
from Crypto.Cipher import AES
from Crypto.Util import strxor
    '''

dbName = "typoToler"
logT = 'LogTable'
hashCachT = 'HashCachTable'
' col: H_typo, salt, count, pk, t_id, '
auxT = 'AuxTable'
waitlistT = 'WaitlistTable'
#allData = 'allData'
orgP_T = "Org_P_Table"


# col: key_id,key. when key_id is the Id of the sk the decrypts the key

# the HashCach will hold the pk as well

'''
SALT_BYTE_LEN = 16
KEY_BYTE_SIZE = 32

def slowHash(typo,salt):
    h_obj = SHA3_512.new()
    h_obj.update(salt+typo)
    return h_obj.hexdigest()

def quickHash(slowHash):
    h_obj = SHA1.new()
    h_obj.update(slowHash)
    return h_obj.hexdigest()

def encryptPub(plain,pk):
    lenP = len(plain)
    lenK = len(pk)
    mostKey = pk * (lenP / lenK)
    rest = pk[:(lenP % lenK)]
    key = mostKey + rest
    return strxor.strxor(plain,key)

def decryptPriv(cipher,sk):
    return encrypt(cipher,sk)

def encryptSym(plain,key):
    return encryptPub(plain,key)

def decryptSym(cipher,key):
    return encryptSym(cipher,key)
'''
def genByteStr(bitslength):   # TODO - will change to something else?
    return random.long_to_bytes(random.getrandbits(bitslength))

class UserTypoDB:
    
    def __init__(self,user):
        self.user = user
        
    def getDB(self): # should we hold the DB connection object as a member?
        return dataset.connect("sqlite:////home/{}/{}.db"\
                               .format(self.user,dbName))

    def init_tables(self,psw):
        db = self.getDB()
        db[logT]
        db[auxT]
        #db[allData]
        db[keysT]

        #db[hashCachT].insert(dict
            
        
    def is_in_cach(self,typo,increaseCount=True):
        '''
        returns the pk of typo if it's in HashCach and it's ID
        if not - returns an emoty string
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

 '''   def get_AES_Key(self,enc_key_id,sk):
        db = self.getDB()
        keyT = db[keysT]
        res = keyT.find(key_id = enc_key_id)
        if len(res) != 1:
            raise Exception('{} results found, 1 expected. key finding'.format(len(res)))
        return decrypt(res[key],sk)'''

    def get_approved_pk_dict(self):
        db = self.getDB()
        cachT = db[hashCachT]
        dic = {}
        for cachLine in cachT:
            typo_id = cachLine[t_id]
            typo_pk = cachLine[pk]
            dic[typo_id] = typo_pk
        return dic
    
    def get_time_str(self):
        return str(time.time())
    
    def add_typo_to_waitlist(self,typo):
        sa = os.urandom(16)
        typo_hs, typo_pk,_ = deriveKey(typo,sa)
        ts = self.get_time_str()
        typo_ctx = encrypt(self.get_approved_pk_dict(),typo)

        db = self.getDB()
        w_list_T = db[waitlistT]

        w_lis_T.insert(dict(ctx = typo_ctx,timestamp = ts))

    def printCachHash(self):
        
        db = self.getDB()
        cachT = db[hashCachT]
        print cachT.columns
        for line in cachT:
            print line

    def cach_insert_policy(self):
        return True
    
    def add_to_hash_cach(self,typo,typo_count = 1,
                         (typo_hash,typo_pk) = ("",""),typo_id = ''):

        if typo_hash == "" or typo_pk == "":
            salt = os.urandom(16)
            typo_hash,typo_pk = derive_public_key(typo,salt)

        if cach_insert_policy():
            pass
        pass

    INIT_PW_COUNT = 1000 # we'll want to change that
    # to ensure the pw protectation actually works
    # and that we won't delete the user's password if he typo-s too much
    def _insert_first_password (self, pw):
        pw_count = 1000
        pass
        
            
    
        
    
            
        

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
    myDB.init_tables("pass")
    ss = slowHash(user,"salt")
    print ss
    print type(ss)
    print int(ss,16)
    ciph = encrypt("aba",ss)
    print "ciph:",ciph
    print "plain:",decrypt(ciph,ss)


    return 0
if __name__ == '__main__':
    main()
    
