VERSION = "1.2.1"
DB_NAME = ".typoToler"
SEC_DB_PATH = '/etc/pam_typtop'
SEC_DB_NAME = DB_NAME + ".ro" # READ_ONLY // ROOT_ONLY

ORIG_SK_SALT = 'OriginalPwSaltForEncSecretKey'
ORIG_PW_CTX = 'OrignalPwCtx'
ORIG_PW_ENTROPY_CTX = 'OrgignalPwEntropyCtx'
HMAC_SALT_CTX = 'HMACSaltCtx'
ORIG_PW_ID = 'OrgPwID'
ORIG_PW_ENC_PK = 'EncPublicKey'
ORIG_PW_SGN_PK = 'SgnPublicKey'
ORIG_SGN_SALT = 'OriginalPwSaltForVerifySecretKey'
REL_ENT_BIT_DEC_ALLOWED = "RelativeEntropyDecAllowed"
LOWEST_ENT_BIT_ALLOWED = "LowestEntBitAllowed"
COUNT_KEY_CTX = "CountKeyCtx"

# default values
CACHE_SIZE = 5
EDIT_DIST_CUTOFF = 1
REL_ENT_CUTOFF = -3
LOWER_ENT_CUTOFF = 10
NUMBER_OF_ENTRIES_BEFORE_TYPOTOLER_CAN_BE_USED = 30

# Tables' names:
logT = 'Log'
logT_cols = {'tid', 'edit_dist', 'rel_entropy', 'ts',
             'istop5fixable', 'in_cache', 'id'}

typocacheT = 'Typocache'
typocacheT_cols = ['H_typo', 'salt', 'count', 'pk', 'top5fixable']

waitlistT = 'Waitlist'
# table col: base64(enc(json(typo, ts, hash, salt, entropy)))'
auxT = 'AuxSysData' # holds system's setting as well as glob_salt and enc(pw)
# table cols: desc, data
secretAuxSysT = "SecretAuxData"
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
