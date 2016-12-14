import os
import json
import pwd
from typtop.dbaccess import (
    UserTypoDB, DB_NAME, get_time,
    on_wrong_password, on_correct_password, logT, logT_cols, auxT,
    find_one, FREQ_COUNTS, INDEX_J, WAITLIST_SIZE, WAIT_LIST,
    compute_id, WARM_UP_CACHE, pkdecrypt, pkencrypt,
    NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN
)
import typtop.config as config
import typtop.dbaccess as dbaccess
import yaml
import pytest
import re
WARM_UP_CACHE = False
NN = 5
secretAuxSysT = "SecretAuxData"
ORIG_PW_ID = 'OrgPwID'

NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN = dbaccess.NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN = 30
dbaccess.WARM_UP_CACHE = 0

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
    db.init_typtop(get_pw(), allow_typo_login=True)
    return db

def test_warmed_cache():
    t1, dbaccess.WARM_UP_CACHE = dbaccess.WARM_UP_CACHE, 1
    t2, dbaccess.NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN = dbaccess.NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN, 0
    typoDB = start_DB()
    assert typoDB.check(pws[1]), pws[1]
    assert typoDB.check(pws[0]), pws[0]
    dbaccess.WARM_UP_CACHE, dbaccess.NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN = t1, t2

def count_real_typos_in_cache(t_db, PW_CHANGE=False):
    flist_ctx = t_db.get_from_auxtdb(FREQ_COUNTS, yaml.load)
    f_list_all = json.loads(pkdecrypt(t_db._sk, flist_ctx))
    f_list = [f for f in f_list_all if f>0]
    return len(f_list), sum(f_list)

def test_login_settings():
    typoDB = start_DB()
    #db = typoDB.getdb()
    assert typoDB.is_allowed_login()
    typoDB.allow_login(allow=False)
    assert not typoDB.is_allowed_login()
    typoDB.allow_login()
    assert typoDB.is_allowed_login()

def test_waitlist(isStandAlone=True):
    typoDB = start_DB()
    pwset = set(pws[:4])
    for i in range(4):
        typoDB.check(pws[i])
    typos_in_waitlist = set()
    for typo_ctx in typoDB.get_from_auxtdb(WAIT_LIST):
        typo_txt = pkdecrypt(typoDB._sk, typo_ctx)
        if re.match(r'\[".*", ".*"\]', typo_txt):
            typo, ts = yaml.safe_load(typo_txt)
            typos_in_waitlist.add(typo)
    assert not (typos_in_waitlist - pwset) and not (pwset - typos_in_waitlist)

def test_add_to_cache(isStandAlone=True):
    typoDB = start_DB()
    indexj = typoDB.get_from_auxtdb(INDEX_J, int)
    typoDB.check(pws[0])
    typoDB.check(pws[0])
    typoDB.check(pws[1])
    typoDB.check(pws[5])
    typoDB.check(pws[2])
    assert (typoDB.get_from_auxtdb(INDEX_J, int) - indexj) % WAITLIST_SIZE == 5
    typoDB.check(get_pw())
    # ntypo, fcount = count_real_typos_in_cache(typoDB)
    # assert ntypo == 3
    # assert fcount > 5

    # No idea what the followig is doing.
    # sk_dict1, isIn_t1 = typoDB.fetch_from_cache(pws[0], False, False)
    # t1_h,_ = sk_dict1.popitem()
    # assert isIn_t1
    # assert hash_t.count(H_typo=t1_h) == 1
    # assert
    # assert hash_t.count(H_typo=t5_h) == 1
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

def test_alt_typo(isStandAlone = True):
    typoDB = test_add_to_cache(False)
    # assert count_real_typos_in_cache(typoDB) > 0
    for _ in xrange(30):
        typoDB.check_login_count(update=True)
    for _ in range(5):
        typoDB.check(pws[4])
    ##    print "added 5 typos to waitlist"
    assert typoDB.check(get_pw())
    assert typoDB.check(pws[4])
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

def test_many_entries(isStandAlone = True):
    print "TEST MANY ENTRIES"
    BIG = 60
    typoDB = start_DB()
    log_t = typoDB.getdb()['Log']
    print "start log:{}".format(len(log_t))
    for typ in listOfOneDist(BIG):
        typoDB.check(typ)
    typoDB.check(get_pw())
    print "log len:{}".format(len(log_t))
    # print "hash len:{}".format(count_real_typos_in_cache(typoDB))
    assert(len(log_t) == WAITLIST_SIZE + 1) # plus the original password
    # realIn = min(BIG, NN)
    # tcnt, fcnt = count_real_typos_in_cache(typoDB)
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

def test_deleting_logs(isStandAlone = True):
    typoDB = start_DB()
    insert = 10
    for i in range(10):
        typoDB.check(pws[i%len(pws)])
    typoDB.check(get_pw())
    log_t = typoDB.getdb()['Log']
    assert len(log_t) == 11 # because that's the length of the log so far
    to_send, log_iter = typoDB.get_last_unsent_logs_iter()
    assert not to_send
    typoDB.update_last_log_sent_time('0')
    to_send,log_iter = typoDB.get_last_unsent_logs_iter()
    count = len(list(log_iter))
    now = get_time()
    typoDB.update_last_log_sent_time(now)
    typoDB.update_last_log_sent_time(now,delete_old_logs=True)
    assert len(log_t) == 0
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

def test_pw_change(isStandAlone = True):
    typoDB = test_alt_typo(isStandAlone = False)
    db = typoDB.getdb()
    typoDB.reinit_typtop(new_pw())
    # assert count_real_typos_in_cache(typoDB,True)[0] == 1
    assert len(db['Log']) == 0
    assert len(db['Waitlist']) == 0
    for newTypo in listOfOneDist(5):
        typoDB.check(newTypo)
    typoDB.check(new_pw())
    # ntypo, ftypo = count_real_typos_in_cache(typoDB, True)
    # assert ntypo == 1
    for newTypo in listOfOneDist(5):
        typoDB.check(newTypo)
    assert not typoDB.check(get_pw())
    if isStandAlone:
        remove_DB()
    else:
        return typoDB

def test_logT(is_stand_alone=True):
    typoDB = start_DB()
    typoDB.allow_login()
    assert typoDB.is_allowed_login()
    assert not on_wrong_password(typoDB, pws[0])
    assert on_correct_password(typoDB, get_pw()) # 1
    assert not on_wrong_password(typoDB, pws[0]) # not enough login count
    for _ in range(NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN-1):
        # on_wrong_password(typoDB, pws[0]) # not enough login count
        assert typoDB.check(get_pw())
        # on_correct_password(typoDB, get_pw())
    assert on_wrong_password(typoDB, pws[0]) # now it should work
    assert set(typoDB._db[logT].columns) == set(logT_cols)
    if is_stand_alone:
        remove_DB()
    else:
        return typoDB
    # TODO: assert some property of logT


# this test takes a bit longer
def test_disabling_first_30_times(isStandAlone = True):
    # checks that entry with a typo is allowed
    # only after the real pw was entered more than 30 times
    typoDB = start_DB()
    assert not on_wrong_password(typoDB, pws[0])
    assert not on_wrong_password(typoDB, pws[1])
    assert on_correct_password(typoDB, get_pw())
    # count = 1
    # 29 left
    for i in xrange(29):
        print "{}th try".format(i)
        assert not on_wrong_password(typoDB, pws[0])
        assert not on_wrong_password(typoDB, pws[1])
        assert on_correct_password(typoDB, get_pw())
    # 30 entries have been done
    assert on_wrong_password(typoDB,pws[0])
    assert on_wrong_password(typoDB,pws[1])

    if isStandAlone:
        remove_DB()
    else:
        return typoDB


def get_pw():
    return 'GoldApp&3'

def new_pw():
    return "Beetle*Juice94"

pws = [
    'goldApp&3',  # 0, lower initial
    'gOLDaPP&3',  # 1, caps
    'GoldApp3',   # 2, dropped 1 char, too low entropy
    'GoldApp&2',  # 3, 1 edit distance
    'GoldApp&35', # 4, 1 edit distance
    'G0ldAppp&3'  # 5, 2 edit dist
]

def listOfOneDist(length):
    # using only lower letters
    # to avoid shift --> 2 edit dist
    m = ord('a')
    M = ord('z') + 1 - m
    for ii in range(length):
        col = ii/M + 1
        newC = chr(ii%M + m)
        typo = get_pw()[:col]+newC+get_pw()[col:]
        yield typo



# pytest.main([__file__])
