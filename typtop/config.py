import sys
VERSION = "0.1.9"

DB_NAME = "typtop"
SEC_DB_PATH = '/etc/typtop.d'
LOG_DIR = '/var/log/'
# SEC_DB_NAME = DB_NAME + ".ro" # READ_ONLY // ROOT_ONL
BINDIR = '/usr/local/bin'  # careful pip install does not guarantee
                           # scripts to be installed at this location.
SYSTEM = ''

def set_distro():
    os = sys.platform
    if os == 'darwin':
        return 'darwin'
    elif os.startswith('linux'):
        try:
            import distro
            dist = distro.id()
            name = distro.name()
        except ImportError:
            dist = 'ubuntu' # default value, will remove DISTRO
            name = 'Ubuntu' # in future.
        # To add new distributions, refer to:
        #    http://distro.readthedocs.io/en/latest/#distro.id
        #    http://linuxmafia.com/faq/Admin/release-files.html
        if dist in ('ubuntu', 'debian'):
            return 'debian'
        elif dist in ('fedora', 'rhel', 'centos'):
            return 'fedora'
        elif dist == 'arch':
            return 'arch'
        else:
            raise ValueError(
                "Not supported for your Linux distribution: {}"\
                .format(name)
            )
    else:
        raise ValueError(
            "Not supported for your OS: {}"\
            .format(os)
        )

DISTRO = set_distro()


def warm_up_with(pw):
    return [
        pw.swapcase(), pw[0].swapcase()+pw[1:],
        pw + '1','1' + pw,
        '`' + pw, pw + '`',
        pw + '0', '0' + pw,
        pw[:-1] + pw[-1] + pw[-1]
    ]

# The group
GROUP = 'shadow' if DISTRO in ('debian') else \
    'root' if DISTRO in ('fedora', 'arch') else \
    'wheel' if DISTRO in ('darwin') \
    else ''

if sys.platform=='darwin':
    SYSTEM = 'OSX'
elif sys.platform.startswith('linux'):
    SYSTEM = 'LINUX'
else:
    raise ValueError("Not yet suporrted. Report in @github/rchatterjee/pam_typopw")

if SYSTEM == 'OSX':
    SEC_DB_PATH = '/usr/local/etc/typtop.d/' # ETC is not writable due to SIP in OSX
elif SYSTEM == 'LINUX':
    SEC_DB_PATH = '/usr/local/etc/typtop.d/'  # Changing from /etc/pam_typtop


################################################################################
                  ########## PARAMETERS ##########
################################################################################
# default values
CACHE_SIZE = 5  # Size of the typo cache
WAITLIST_SIZE = 10   # Size of the waitlist
PADDED_PW_SIZE = 64  # length of the padded passwords
EDIT_DIST_CUTOFF = 1.0/10  # fractional distance between the real
                           # password and the typo, 1 typo per 10
                           # characters
REL_ENT_CUTOFF = 3 # Typo cannot be less than 3 bits in stregth
                   # compared to the real password
LOWER_ENT_CUTOFF = 10
NUMBER_OF_ENTRIES_TO_ALLOW_TYPO_LOGIN = 0  # Number of successful login   (# TODO: set to 30 when done testing)
NUMBER_OF_DAYS_TO_ALLOW_TYPO_LOGIN = 15  # Number of days since installation
UPDATE_GAPS= 24 * 60 * 60 # 24 hours, in seconds
WARM_UP_CACHE = 1  # Should the cache be warmed up or not.
################################################################################


# column names in sqlite tables
auxT = 'Header' # holds most of the system's setting
# in ENCRYPTED format
HEADER_CTX = 'HeaderCtx'
HMAC_SALT = 'HMACSalt'
FREQ_COUNTS = 'FreqCounts'
REAL_PW = 'RealPassword'

# in PLAINTEXT format
ENC_PK = 'EncPublicKey'
INDEX_J = 'IndexJ'
# for book keeping
ALLOWED_TYPO_LOGIN = 'AllowedTypoLogin'
LOGIN_COUNT = 'LoginCount'
INSTALLATION_ID = 'InstallationId'
INSTALLATION_DATE = 'InstallationDate'
ALLOWED_LOGGING = 'AllowLogging'
LOG_LAST_SENTTIME = 'LastLogSetntTime'
LOG_SENT_PERIOD = 'PeriodForSendingLog' # How frequently to send the logs
SYSTEM_STATUS = 'SystemStatus'
SYSTEM_STATUS_PW_CHANGED = 'PasswordChanged'
SYSTEM_STATUS_ALL_GOOD = 'StatusAllGood'
SYSTEM_STATUS_CORRUPTED_DB = 'StatusCorruptedDB'
SYSTEM_STATUS_NOT_INITIALIZED = 'NotInitialized'

# Typo Cache and Wait list are stored as just another data field in
# Header. No need to have different tables for them.
TYPO_CACHE = "TypoCache"  # PW Encryption of sk
WAIT_LIST = 'WaitList'  # PK encryption of typo and timestamp

# ORIG_PW = 'OrignalPw'
# ORIG_PW_ID = 'OrgPwID'  # Remove
# ORIG_PW_ENTROPY_CTX = 'OrgignalPwEntropyCtx'
# ORIG_PW_SGN_PK = 'SgnPublicKey'
# ORIG_SGN_SALT = 'OriginalPwSaltForVerifySecretKey'
# REL_ENT_CUTOFF = "RelativeEntropyDecreaseAllowed"
# MIN_ENT_CUTOFF = "LowestEntropyAllowed"
# COUNT_KEY_CTX = "CountKeyCtx"
# HMAC_SALT_CTX = 'HMACSaltCtx'



logT = 'Log'
logT_cols = [
    'tid', 'edit_dist', 'rel_entropy', 'ts',
    'istop5fixable', 'in_cache'
]
