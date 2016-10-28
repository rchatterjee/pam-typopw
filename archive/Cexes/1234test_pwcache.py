import pytest
from pwcache import PwCache, salt

pwch = PwCache()
class TestPwCache(object):
    pass

def test_put():
    pwch.put('rahul', 'abcd123')
    pwch.initialize('rahul', 'abcds234', 'asdfadf')
    print pwch.get('rahul')

if __name__ == "__main__":
    test_put()
    
