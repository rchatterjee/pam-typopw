import os
import pwd
from adaptive_typo.typo_db_access import (
    UserTypoDB,
    DB_NAME,
    waitlistT,
    hashCacheT,
    get_time_str
)
from adaptive_typo.pw_pkcrypto import (
    encrypt, decrypt, derive_public_key,
    derive_secret_key, update_ctx, compute_id
)
import pytest

NN = 5

def get_username():
    return pwd.getpwuid(os.getuid()).pw_name

def DB_path():
    # TODO _ for some reason it does't work
    user = get_username()
    db = UserTypoDB(user, debug_mode=True)
    return db.get_db_path()
    #return "/home/{}/{}.db".format(get_username(), DB_NAME)

def remove_DB():
    os.remove(DB_path())

def start_DB():
    remove_DB()
    db = UserTypoDB(get_username(), debug_mode=True)
    db.init_typotoler(get_pw(), NN)
    return db

def test_login_settings():
    typoDB = start_DB()
    #db = typoDB.getdb()
    assert typoDB.is_allowed_login()
    typoDB.allow_login(allow=False)
    assert not typoDB.is_allowed_login()
    typoDB.allow_login()
    assert typoDB.is_allowed_login()
    
def test_added_to_hash(isStandAlone = True):
    typoDB = start_DB()
    typoDB.add_typo_to_waitlist(t_1())
    typoDB.add_typo_to_waitlist(t_1())
    # typoDB.add_typo_to_waitlist(t_2())
    typoDB.add_typo_to_waitlist(t_5())
    typoDB.add_typo_to_waitlist(t_3())
    assert len(typoDB.getdb()[waitlistT]) == 4
    typoDB.original_password_entered(get_pw())
    
    assert len(typoDB.getdb()[waitlistT]) == 0
    hash_t = typoDB.getdb()[hashCacheT]
    assert len(hash_t) == 2
    sk_dict1, isIn_t1 = typoDB.fetch_from_cache(t_1(), False, False)
    t1_h,_ = sk_dict1.popitem()
    assert isIn_t1
    assert hash_t.count(H_typo=t1_h) == 1
    #_, t2_h, isIn_t2 = typoDB.fetch_from_cache(t_2(), False, False)
    sk_dict5, isIn_t5 = typoDB.fetch_from_cache(t_5(), False, False)
    t5_h, _ = sk_dict5.popitem()
    assert isIn_t5
    assert hash_t.count(H_typo=t5_h) == 1
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

def test_alt_typo(isStandAlone = True):
    print "TEST ALT TYPO"
    typoDB = test_added_to_hash(False)
    hash_t = typoDB.getdb()[hashCacheT]
    assert len(hash_t) > 0
    count = len(hash_t)
    for ii in range(5):
        typoDB.add_typo_to_waitlist(t_4())
    ##    print "added 5 typos to waitlist"
    sk_dict1, isIn_t1 = typoDB.fetch_from_cache(t_1(), False, False)
    t1_h, t1_sk = next(sk_dict1.iteritems())
    typo_hash_line = hash_t.find_one(H_typo=t1_h)
    assert typo_hash_line
    pk = typo_hash_line['pk']
    salt = typo_hash_line['salt']
    assert isIn_t1
    typoDB.update_hash_cache_by_waitlist(sk_dict1)
    assert len(hash_t) == count+1
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

@pytest.mark.skip('')
def test_many_entries(isStandAlone = True):
    print "TEST MANY ENTRIES"
    BIG = 60

    typoDB = start_DB()
    
    log_t = typoDB.getdb()['Log']
    hash_t = typoDB.getdb()['HashCache']
    wait_t = typoDB.getdb()['Waitlist']

    print "start log:{}".format(len(log_t))
    
    for typ in listOfOneDist(BIG):
        typoDB.add_typo_to_waitlist(typ)
    print "waitlist len:{}".format(len(wait_t))
    assert (len(wait_t) == BIG)
    typoDB.original_password_entered(get_pw())
    print "log len:{}".format(len(log_t))
    print "hash len:{}".format(len(hash_t))
    assert(len(log_t) == BIG+1 ) # plus the original password
    realIn = min(BIG, NN)
    assert (len(hash_t) == realIn)
    if isStandAlone:
        remove_DB()
    else:
        return typoDB
    
def test_deleting_logs(isStandAlone = True):
    typoDB = test_alt_typo(isStandAlone = False)
    log_t = typoDB.getdb()['Log']
    assert len(log_t) == 10 # because that's the length of the log so far
    to_send,log_iter = typoDB.get_last_unsent_logs_iter()
    assert not to_send
    typoDB.update_last_log_sent_time('0')
    to_send,log_iter = typoDB.get_last_unsent_logs_iter()
    count = 0;
    for ll in log_iter:
        count += 1
    now = get_time_str()
    typoDB.update_last_log_sent_time(now)
    assert len(log_t) == 10
    typoDB.update_last_log_sent_time(now,delete_old_logs=True)
    assert len(log_t) == 0
    if isStandAlone:
        remove_DB()
    else:
        return typoDB
    
def test_pw_change(isStandAlone = True):
    typoDB = test_alt_typo(isStandAlone = False)
    db = typoDB.getdb()
    typoDB.update_after_pw_change(new_pw())
    assert len(db['HashCache']) == 0
    assert len(db['Log']) == 0
    assert len(db['Waitlist']) == 0
    failed_to_decrypt_with_old_pw = False
    with_new_pw = True
    try:
        for newTypo in listOfOneDist(5):
            typoDB.add_typo_to_waitlist(newTypo)
        typoDB.original_password_entered(new_pw())
        assert len(db['HashCache']) == 0        
        with_new_pw = False
        for newTypo in listOfOneDist(5):
            typoDB.add_typo_to_waitlist(newTypo)    
        typoDB.original_password_entered(get_pw())
    except KeyError as e:
        # encryption error
        if not with_new_pw:
            failed_to_decrypt_with_old_pw = True
        else:
            # i.e - failed with the new pw:
            assert 0
    except ValueError as e:
        # probably a verify error
        if not with_new_pw:
            failed_to_decrypt_with_old_pw = True
        else:
            # i.e - failed with the new pw:
            assert 0
    finally:
        if isStandAlone:
            remove_DB()
        else:
            return typoDB

    
def get_pw():
    return 'GoldApp&3'

def new_pw():
    return "Beetle*Juice94"

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
    # using only lower letters
    # to avoid shift --> 2 edit dist
    m = ord('a')
    M = ord('z') + 1 - m
    for ii in range(length):
        col = ii/M + 1
        newC = chr(ii%M + m)
        typo = get_pw()[:col]+newC+get_pw()[col:]
        ll.append(typo)
        
    return ll
    
    

# "main"
##print str(listOfOneDist(60))
##print get_username()
##print DB_path()
##print str(start_DB())
# print "************* test_login_settings ******************"
# test_login_settings()
# print "************* test_added_to_hash ******************"
# test_added_to_hash()
# print "************* test_many_entries ******************"
# test_many_entries()
# print "************* test_alt_typo ******************"
# test_alt_typo(False)
