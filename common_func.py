import string
CASE_LOWER = '<lower>'
CASE_UPPER = '<upper>'
CASE_TITLE = '<title>'

user_friendly = 0
BLANK = [u'\x00', '*'][user_friendly]   # '\b'
STARTSTR = [u'\x01', '^'][user_friendly]
ENDSTR = [u'\x02', '$'][user_friendly]

SHIFT_KEY = [u'\x03', "<s>"][user_friendly]
CAPS_KEY = [u'\x04', "<c>"][user_friendly]

ALLOWED_KEYS = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./ "
ALLOWED_CHARACTERS = string.letters + string.digits + '`~!@#$%^&*()_+-=,/?.<>;\':"[]{}\\| \t'

ALLOWED_KEYS += BLANK + SHIFT_KEY + CAPS_KEY + STARTSTR + ENDSTR

### Future work to do it on ALLOWED_KEYS ##
ALLOWED_CHARACTERS += BLANK + STARTSTR + ENDSTR

TYPO_FIX_PROB = {
    "rm-lastl": 59, 
    "rm-firstc": 55, 
    "swc-all": 1698, 
    "sws-lastn": 14, 
    "rm-lastd": 60, 
    "upncap": 13, 
    "same": 90234, 
    "swc-first": 209, 
    "sws-last1": 19, 
    "cap2up": 5, 
    "n2s-last": 9, 
    "add1-last": 5, 
    "rm-lasts": 72,
    "kclose": 1385,
    "other": 1918,
    "tcerror": 18,
    "rm-lastc": 191
}

def dp(**kwargs):
    print ''
    print '\t'.join("%s: %s" % (k,str(v)) \
                    for k,v in kwargs.items())

def what_case(w):
    return CASE_TITLE if w.istitle() \
        else CASE_LOWER if w.islower() \
        else CASE_UPPER
