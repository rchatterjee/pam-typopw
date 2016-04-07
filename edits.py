__author__ ='Rahul Chatterjee'

import os, sys, json, csv
import string, re
import unittest, string
from collections import defaultdict
from common_func import *

ALLOWED_CHARS = ALLOWED_CHARACTERS[:-3]
NOTSHIFT_2_SHIFT_MAP = dict(zip('`1234567890-=[]\;\',./',
                                '~!@#$%^&*()_+{}|:"<>?'))
SHIFT_2_NOTSHIFT_MAP = dict(zip('~!@#$%^&*()_+{}|:"<>?',
                                '`1234567890-=[]\;\',./'))
SHIFT_SWITCH_MAP = dict(zip('`1234567890-=[]\;\',./~!@#$%^&*()_+{}|:"<>?',
                            '~!@#$%^&*()_+{}|:"<>?`1234567890-=[]\;\',./'))
SYMDIGIT_re = re.compile(r'(?P<last>(%s)+)$' % '|'.join(map(re.escape, SHIFT_SWITCH_MAP.keys())))


class Edits(object):       
    shift_swtich_regex = re.compile(r'(?P<last>(%s)+)$' % '|'.join(map(re.escape, SHIFT_SWITCH_MAP.keys())))
    def __init__(self):
        # This is a funcname to func map, first entry in the value part is transform, 
        # second one is the typos that it can fix.
        self.EDITS_NAME_FUNC_MAP = {
            "same": [self.same, self.same],
            "swc-all": [self.switch_case_all, self.switch_case_all],  # insertion of caps-lock
            "swc-first": [self.switch_case_first, self.switch_case_first],  # deletion of shift
            "add1-last": [self.add1_last, self.remove1_last],  # missed last 1
            "rm-lastl": [self.remove_last_letter, self.add_last_letter],  # addion of a char
            "rm-lastd": [self.remove_last_digit, self.add_last_digit],  # addion of a digit
            "rm-lasts": [self.remove_last_symbol, self.add_last_symbol],  # addtion of a symbol
            "rm-firstc": [self.remove_first_char, self.add_first_char],  # addition of a char at the beginning
            "rm-lastc": [self.remove_last_char, self.add_last_char],  # addition of a char at the end
            "sws-last1": [self.switch_shift_last1, self.switch_shift_last1],  # deletion of last shift
            "sws-lastn": [self.switch_shift_lastn, self.switch_shift_lastn],  # deletion of last shift
            "upncap": [self.upper_n_capital, self.upper_n_capital],  # typed caps instead of shift switch
            # "up2cap": [self.upper_2_capital, self.upper_2_capital],  # typed caps instead of shift switch
            # "cap2up": [self.capital_2_upper, self.upper_2_capital],  # typed shift instead of caps switch
            "n2s-last": [self.n2s_last, self.s2n_last] # convert last number to symbol
        }
        self.ALLOWED_EDITS = self.EDITS_NAME_FUNC_MAP.keys()

    def same(self, word):
        return word

    def _switch_case_letter(self, ch):
        if ch.islower():
            return ch.upper()
        else:
            return ch.lower()

    def switch_case_all(self, word):
        w =  word.swapcase()
        if w != word:
            return w

    def switch_case_first(self, word):
        i = 0
        while i<len(word) and not word[i].isalpha():
            i+=1
        if i<len(word):
            return word[:i] + self._switch_case_letter(word[i]) + word[i+1:]
    
    def upper_n_capital(self, word):
        if word.isupper():
            return word.title()
        elif word.istitle():
            return word.upper()
        
    def upper_2_capital(self, word):
        if word.isupper():
            return word.title()


    def capital_2_upper(self, word):
        if word.istitle():
            return word.upper()

    def add1_last(self, word):
        return word + '1'

    def remove1_last(self, word):
        if word[-1] == '1':
            return word[:-1] 

    def remove_last_digit(self, word):
        if word[-1].isdigit():
            return word[:-1]

    def remove_last_symbol(self, word):
        if not word[-1].isalnum():
            return word[:-1]

    def remove_last_letter(self, word):
        if word[-1].isalpha():
            return word[:-1]

    def remove_first_char(self, word):
        return word[1:]

    def remove_last_char(self, word):
        return word[:-1]

    def add_last_digit(self, word):
        return [word+c for c in string.digits]

    def add_last_symbol(self, word):
        return [word+c for c in string.punctuation]

    def add_last_letter(self, word):
        return [word+c for c in string.ascii_letters]

    def add_first_char(self, word):
        return [c+word for c in ALLOWED_CHARS]

    def add_last_char(self, word):
        return [word+c for c in ALLOWED_CHARS]

    def _change_shift_status_last(self, word, shift_map):
        shift_regex = re.compile(r'(?P<last>(%s)+)$' % '|'.join(map(re.escape, shift_map.keys())))
        def _replace_(mo):
            text = mo.string[mo.start():mo.end()]
            return ''.join(shift_map.get(ch, ch) for ch in text)

        return shift_regex.sub(_replace_, word)

    def switch_shift_lastn(self, word):
        """
        change the shift state of last digit+symbols string
        e.g., "asdf123" -> "asdf!@#"
        """
        done = 0;
        new_str = list(word)
        for i in xrange(len(word),0,-1):
            if not done:
                try:
                    new_str[i-1] = SHIFT_SWITCH_MAP[word[i-1]]
                except:
                    break
        w = ''.join(new_str)
        if w != word:
            return w
        # return self._change_shift_status_last(word, SHIFT_SWITCH_MAP)

    def n2s_last(self, word):
        if word[-1].isdigit():
            return self.switch_shift_last1(word)

    def s2n_last(self, word):
        if not word[-1].isalnum():
            return self.switch_shift_last1(word)

    def add_shift_lastn(self, word):
        """
        if the last digit+symbol string is not shifted, shift it
        """
        return self._change_shift_status_last(word, NOTSHIFT_2_SHIFT_MAP)

    def remove_shift_lastn(self, word):
        """
        if the last digit+symbol string is not shifted, shift it
        """
        return self._change_shift_status_last(word, NOTSHIFT_2_SHIFT_MAP)

    def switch_shift_last1(self, word):
        ch = word[-1]
        return word[:-1] + SHIFT_SWITCH_MAP.get(ch, ch)

    def add_shift_last1(self, word):
        ch = word[-1]
        return word[:-1] + NOTSHIFT_2_SHIFT_MAP.get(ch, ch)

    def remove_shift_last1(self, word):
        ch = word[-1]
        return word[:-1] + SHIFT_2_NOTSHIFT_MAP.get(ch, ch)

    def modify(self, word, apply_edits=["All"], typo=False):
        """
        If typo is True, then apply the reverse edits, i.e., self.EDIT_TO_TYPOS
        returns:   {tpw: set of edits that will convert word to tpw}
        in case typo is true, then it will be {tpw: set of words that can be edited back to word}
        """
        if 'All' in apply_edits:
            apply_edits = self.ALLOWED_EDITS
        mutated_words = defaultdict(set)
        istypo = 1 if typo else 0
        # return the ball that will be accepted due to allowing these edits
        allowed_edits = set(self.EDITS_NAME_FUNC_MAP[a][istypo] for a in apply_edits)
        for e in allowed_edits:
            tpw = e(word)
            if isinstance(tpw, basestring):
                mutated_words[tpw].add(e)
            else:
                for t in tpw:
                    mutated_words[t].add(e)
        return mutated_words

    def fast_modify(self, word, apply_edits=["All"], typo=False, pw_filter=None):
        """
        If typo is True, then apply the reverse edits, i.e., self.EDIT_TO_TYPOS
        returns:   {tpw: set of edits that will convert word to tpw}
        in case typo is true, then it will be {tpw: set of words that can be edited back to word}
        """
        # if not pw_filter(word):
        #     print "I am modifying a password ('{}') which does not pass its own filter ({})"\
        #     .format(word, pw_filter)
        if not pw_filter:
            pw_filter = lambda x: len(x)>=6

        if 'All' in apply_edits:
            apply_edits = self.ALLOWED_EDITS
        mutated_words = set()
        istypo = 1 if typo else 0
        # if istypo --- returns the ball that will be accepted due to allowing these edits
        # else --- return the candidate real passwords after apllying the edits.
        for a in apply_edits:
            e = self.EDITS_NAME_FUNC_MAP[a][istypo]
            tpw = e(word)
            if not tpw:
                # print "Tpw='{}' is None for rpw='{}' "\
                #     "a={} and e={}".format(tpw, word, a, str(e))
                continue
            if isinstance(tpw, basestring):
                tpw = [tpw]
            assert isinstance(tpw, list), "WTF!! tpw ('{!r}') is of type = {}".format(tpw, type(tpw))
            mutated_words |= set(filter(pw_filter, tpw))
        return mutated_words
        
    def check_invalid_edits(self, edits):
        assert all(e in self.ALLOWED_EDITS for e in edits), "Some edit is not in the list: {}".format(edits)

        
def main():
    unittest.main()
    # get_stat_of_edits(config.ALLOWED_EDITS, config.POLICY)
    exit(0)
    E = Edits()
    allowed_edits = E.ALLOWED_EDITS[:4]
    print allowed_edits
    T = E.fast_modify('bianca', allowed_edits)
    for t in T:
        print t, ">>>",
        print E.fast_modify(t, allowed_edits, typo=True, \
                            pw_filter=lambda x: len(x)>=6)
    exit(0)
    L = []
    for k,v in json.load(open(sys.argv[1])).items():
        for x in v:
            if k!= x[0]:
                L.append((k,x[0]))
    all_edits = Edits()
    print "Total typo:", len(L)
    for i in range(1,10):
        A = [0 for  orig, typed in L
             if orig in all_edits.modify(typed, till=i)
        ]
        print len(A)
