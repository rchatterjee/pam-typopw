/*
 * File containing utility functions to read and write password
 * file. Also, sorting the pw-cache entries.
 * 
 */

#include <stdlib.h>
#include <crypt.h>
#include <unistd.h>
#include "util.h"

/*
 * getusercache returns an pwcache object that contain all the stored
 * entries of passwords (real and mistyped) for the user @username's
 * acconut. Returns null if the user not found. 
 */
struct pwcache* getuserchache(char *username) {
}

/* Returns the entries for each user */
struct pwcache* read_pwfile() {
    FILE *fp = fopen(PW_CACHE_FILE);
    if (!fp) {
        pritnf("ERROR: the specified file (%s) could not found", PW_CACHE_FILE);
        return NULL;
    }
    int line_size = sizeof(pwcache);
    char tmp_line[1024];

    while (!feof(fp)) {
	  getdelim(, line_size, fp);
      char *tokens = strtok(tmp_line, ":");
      while (tokens != NULL) {
            

