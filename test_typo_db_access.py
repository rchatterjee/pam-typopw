import os
import pwd
from adaptive_typo.typo_db_access import UserTypoDB,DB_NAME,waitlistT,hashCachT


NN = 5

def get_username():
    return pwd.getpwuid(os.getuid()).pw_name

def DB_path():
    # TODO _ for some reason it does't work
    db = UserTypoDB(get_username())
    return db.get_DB_path()
    #return "/home/{}/{}.db".format(get_username(),DB_NAME)

def remove_DB():
    os.remove(DB_path())

def start_DB():
    remove_DB()
    db = UserTypoDB(get_username())
    db.init_typotoler(get_pwd(),NN)
    return db

def test_login_settings():
    typoDB = start_DB()
    #db = typoDB.getDB()
    assert(typoDB.is_allowed_login() == True)
    typoDB.disallow_login()
    print typoDB.is_allowed_login()
    assert(typoDB.is_allowed_login() == False)
    typoDB.allow_login()
    assert(typoDB.is_allowed_login() == True)
    
def test_added_to_hash():
    typoDB = start_DB()
    typoDB.add_typo_to_waitlist(t_1())
    typoDB.add_typo_to_waitlist(t_1())
    # typoDB.add_typo_to_waitlist(t_2())
    typoDB.add_typo_to_waitlist(t_5())
    typoDB.add_typo_to_waitlist(t_3())
    assert( len(typoDB.getDB()[waitlistT]) == 4) 
    typoDB.original_password_entered(get_pwd())
    assert( len(typoDB.getDB()[waitlistT]) == 0)
    hash_t = typoDB.getDB()[hashCachT]
    assert( len(hash_t) == 2)
    _,t1_h,isIn_t1 = typoDB.fetch_from_cache(t_1(),False,False)
    assert (isIn_t1)
    assert(hash_t.find_one(H_typo=t1_h)['count'] == 2)
    #_,t2_h,isIn_t2 = typoDB.fetch_from_cache(t_2(),False,False)
    _,t2_h,isIn_t2 = typoDB.fetch_from_cache(t_5(),False,False)
    assert (isIn_t2)
    assert(hash_t.find_one(H_typo=t2_h)['count'] == 1)
    return typoDB

def test_alt_typo():
    typoDB = test_added_to_hash()
    hash_t = typoDB.getDB()[hashCachT]
    count = len(hash_t)
    for ii in range(5):
        typoDB.add_typo_to_waitlist(t_4())
    t1_sk,t1_h,isIn_t1 = typoDB.fetch_from_cache(t_1(),False,False)
    typoDB.update_hash_cach_by_waitlist(t1_sk,r1_h)
    
    assert (len(hash_t) == count+1)

def test_many_entries():
    BIG = 60

    typoDB = start_DB()
    
    log_t = typoDB.getDB()['Log']
    hash_t = typoDB.getDB()['HashCache']
    wait_t = typoDB.getDB()['Waitlist']

    print "start log:{}".format(len(log_t))
    
    for typ in listOfOneDist(BIG):
        typoDB.add_typo_to_waitlist(typ)
    print "waitlist len:{}".format(len(wait_t))
    assert (len(wait_t) == BIG)
    typoDB.original_password_entered(get_pwd())
    print "log len:{}".format(len(log_t))
    print "hash len:{}".format(len(hash_t))
    assert(len(log_t) == BIG+1 )
    realIn = max(BIG,NN)
    assert (len(hash_t) == realIn)
    
    

def get_pwd():
    return 'GoldApp&3'

def t_1():
    # lower initial
    return 'goldApp&3' 

def t_2():
    # caps
    return 'gOLDaPP&3'

def t_3():
    # dropped char
    # reduce entropy too much
    return 'GoldApp3'

def t_4():
    # 1 edit distance
    return 'GoldApp&2'

def t_5():
    return 'GoldApp&35'

def t_6():
    # 2 edit dist
    return 'G0ldAppp&3'

def listOfOneDist(length):
    ll = []
    m = 32
    M = 65 - m
    for ii in range(length):
        col = ii/M + 1
        newC = chr(ii%M + m)
        typo = get_pwd()[:col]+newC+get_pwd()[col:]
        ll.append(typo)
    #for i in range(length):
    #    col = i/33
    #    newC = chr(32+i%33)
    #    typo = get_pwd()[:col-1]+newC+get_pwd()[col+1:]
    #    print typo
    #    ll.append(typo)
        
    return ll
    
    

# "main"
print str(listOfOneDist(60))
print get_username()
print DB_path()
print str(start_DB())
test_login_settings()
test_added_to_hash()
test_many_entries()
