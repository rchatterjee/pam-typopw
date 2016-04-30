#infndef UTIL_H
#define UTIL_H
// 10 extra passwords will be stored in the cache excluding the original password.
// The cache will be initialized with junk, and latter, it will be replaced with
// recent/more frequent typos.
#define CACHE_SIZE 11  // this must be greater than or equal to 1
#define PW_CACHE_FILE "./passwords"  // TODO - change it accordingly
#define MAX_PW_SIZE 255
#define MAX_USERNAME_SIZE 255

struct pwcacheentry {
    char tp_pw[MAX_PW_SIZE];
    int count=0;
};

struct pwcache {
    char tp_namp[MAX_USERNAME_SIZE];
    struct cache tp_cache[CACHE_SIZE];
};

#endif
