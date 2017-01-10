/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>

#include <security/pam_appl.h>


int
main (void)
{
  const char *service = "dummy";
  const char *user = "root";
  struct pam_conv conv;
  pam_handle_t *pamh;
  int retval;

  /* 1: close valid pam handle */
  /* create valid pam handle */
  retval = pam_start (service, user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr, "pam_start (%s, %s, &conv, &pamh) returned %d\n",
	       service, user, retval);
      return 1;
    }

  retval = pam_end (pamh, 0);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr, "pam_end (pamh, 0) returned %d\n", retval);
      return 1;
    }

  /* 2: close NULL pam handle */
  retval = pam_end (NULL, 0);
  if (retval == PAM_SUCCESS)
    {
      fprintf (stderr, "pam_end (NULL, 0) returned %d\n", retval);
      return 1;
    }

  return 0;
}
