#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <unistd.h>

int main( int argc, char** argv ) 
{
  struct spwd* sp;

  // setup_signals();
  /*
   * we establish that this program is running with non-tty stdin.
   * this is to discourage casual use. It does *NOT* prevent an
   * intruder from repeatadly running this program to determine the
   * password of the current user (brute force attack, but one for
   * which the attacker must already have gained access to the user's
   * account).
   */
   
  if (isatty(STDIN_FILENO) || argc != 2 ) {
    fprintf(stderr
            ,"This binary is not designed for running in this way\n"
            "-- the system administrator has been informed\n");
    sleep(10);  /* this should discourage/annoy the user */
    return EXIT_FAILURE;
  }

  if (argc < 2) {
    fprintf(stderr, "%s username \n", argv[0]);
    return(EXIT_FAILURE);
  }

  if( ( sp = getspnam( argv[1] ) ) == (struct spwd*)0) {
    fprintf( stderr, "getspnam: unknown <%s>\n",
             argv[1] );
    return( EXIT_FAILURE );
  }
  /* printf( "login name  %s\n", sp->sp_namp ); */
  /* printf( "password    %s\n", sp->sp_pwdp ); */
  char pw[1000+1];
  while(fgets(pw, 1000, 0) != NULL) { // 0 is fileno of stdin, at most
                                      // 1000 chars
      const char *crypt_password;      
      printf("Trying: <%s>\n", pw);
      if (((crypt_password = crypt(pw, sp->sp_pwdp)) != NULL) &&
          strcmp(crypt_password, sp->sp_pwdp) == 0) {
        printf("This one worked! %s\n", pw);
        return (EXIT_SUCCESS);  // If it succeeds, then set
                                // pam_success and don't do anything
      }
    }
  printf("Failed!!!\n");
  return( EXIT_FAILURE );
}
