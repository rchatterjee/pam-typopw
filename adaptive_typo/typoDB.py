import dataset
import sys
import time
from Crypto.Random import random

# will be REMOVED
from Crypto.Hash import SHA3_512
from Crypto.Hash import SHA1
from Crypto.Cipher import AES
from Crypto.Util import strxor


    
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


def encrypt (dic = {}, m = ""):
    pass

def decrypt(dic = {}, c = ""):
    pass

def deriveKey(pw,sa):
    pass

def compute_id(pw,dic = {},ctxsalt):
    pass


class UserTypoDB:
    
    def __init__(self,user):
        self.user = user
        
    def getDB(self): # should we hold the DB connection object as a member?
        return dataset.connect("sqlite:////home/{}/{}.db"\
                               .format(self.user,dbName))

    def initTables(self,psw):
        db = self.getDB()
        db[logT]
        db[auxT]
        #db[allData]
        db[keysT]

        #db[hashCachT].insert(dict
            
        
    def isInCach(self,typo):
        '''
        returns the pk of typo if it's in HashCach and it's ID
        if not - returns an emoty string
        ''' # in python2.7 hex is a string
        db = self.getDB()
        cachT = db[hashCachT]
        for CachLine in cachT:
            sa = CachLine[salt]
            hs,pk,sk = deriveKey(typo,sa)
            hsInTable = CachLine[H_typo]
            typo_id = CachLine[t_id]
            if hsInTable == hs:
                return sk,typo_id

        return '',''

    def sortCach(self):
        pass
        # when we sort the cach we need to reCalc the pwd encryption and reCalc the keysTable

 '''   def get_AES_Key(self,enc_key_id,sk):
        db = self.getDB()
        keyT = db[keysT]
        res = keyT.find(key_id = enc_key_id)
        if len(res) != 1:
            raise Exception('{} results found, 1 expected. key finding'.format(len(res)))
        return decrypt(res[key],sk)'''

    def getApprovedTypoPkDict(self):
        db = self.getDB()
        cachT = db[hashCachT]
        dic = {}
        for cachLine in cachT:
            typo_id = cachLine[t_id]
            typo_pk = cachLine[pk]
            dic[typo_id] = typo_pk
        return dic

    def getTimeStr(self):
        return str(time.time())
    
    def addNewTypoToWaitList(self,typo):
        sa = genByteStr(128)
        typo_hs, typo_pk,_ = deriveKey(typo,sa)
        ts = 
        ctx = encrypt(self.getApprovedTypoPkDict(),typo)

        db = self.getDB()
        w_list_T = db[waitlistT]
        
        
        
        
    
            
        

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
    myDB.initTables("pass")
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
    
