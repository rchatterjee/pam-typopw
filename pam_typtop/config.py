VERSION = "1.2.7"
DB_NAME = "typtop"
SEC_DB_PATH = '/etc/pam_typtop'
LOG_DIR = '/var/log/'
# SEC_DB_NAME = DB_NAME + ".ro" # READ_ONLY // ROOT_ONL
BINDIR = '/usr/local/bin'

# default values
CACHE_SIZE = 5
EDIT_DIST_CUTOFF = 1
REL_ENT_CUTOFF = -3
LOWER_ENT_CUTOFF = 10
NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED = 30

colname_ORIG_PW_CTX = 'OrignalPwCtx'
# ORIG_PW_ENTROPY_CTX = 'OrgignalPwEntropyCtx'
colname_ORIG_PW_ID = 'OrgPwID'
colname_ORIG_PW_ENC_PK = 'EncPublicKey'
# ORIG_PW_SGN_PK = 'SgnPublicKey'
# ORIG_SGN_SALT = 'OriginalPwSaltForVerifySecretKey'
colname_REL_ENT_CUTOFF = "RelativeEntropyDecAllowed"
colname_LOWEST_ENT_BIT_ALLOWED = "LowestEntBitAllowed"
colname_COUNT_KEY_CTX = "CountKeyCtx"
colname_HMAC_SALT_CTX = 'HMACSaltCtx'


# Tables' names:
logT = 'Log'
logT_cols = {'tid', 'edit_dist', 'rel_entropy', 'ts',
             'istop5fixable', 'in_cache', 'id'}

# TODO: Convert in a plain json file
typocacheT = 'Typocache'
typocacheT_cols = ['encryption_of_sk']

waitlistT = 'Waitlist'
# table col: base64(enc(json(typo, ts, hash, salt, entropy)))'
auxT = 'AuxSysData' # holds system's setting as well as glob_salt and enc(pw)
# table cols: desc, data
# secretAuxSysT = "SecretAuxData"
# table cols: desc, data

# auxiley info 'desc's:
AllowedTypoLogin = "AllowedTypoLogin"
InstallDate = "InstallDate"
InstallationID = "Install_id"
LastSent="Last_sent"
SendEvery="SendEvery(sec)"
UPDATE_GAPS= 24 * 60 * 60 # 24 hours, in seconds
AllowUpload = "AllowedLogUpload"
LoginCount = 'NumOfLogins' # counts logins of real pw only
FreqList = 'TypoFrequencies'
# - in order to avoid early entry which will change the collected data
# - initiated by typotoler_init. not re-initiated by re-init

SysStatus = "PasswordHasBeenChanged"
CacheSize = "CacheSize"
EditCutoff = "EditCutoff"  # The edit from which (included) it's too far
# PwAcceptPolicy = "PwAcceptPolicy"   # not yet implemented
# LastPwChange = "LastPwChange"  # not yet implemented

rel_bit_strength = 'rel_bit_str'
