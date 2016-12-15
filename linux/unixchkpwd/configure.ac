#              -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([typo_chkpwd], [1.0.1], [rahul@cs.cornell.edu])
# AC_CONFIG_SRCDIR([unix_chkpwd.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

AC_PREFIX_DEFAULT(/)

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_YACC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_CC_C_O

AH_VERBATIM([_GNU_SOURCE],
[/* Enable GNU extensions on systems that have them.  */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif])


if test "x${CC_FOR_BUILD+set}" != "xset" ; then
  if test "x$cross_compiling" = "xyes" ; then
    AC_CHECK_PROGS(CC_FOR_BUILD, gcc cc)
  else
    CC_FOR_BUILD=${CC}
  fi
fi
AC_MSG_CHECKING([for CC_FOR_BUILD])
AC_MSG_RESULT([$CC_FOR_BUILD])
AC_SUBST(CC_FOR_BUILD)

if test "x${BUILD_CFLAGS+set}" != "xset" ; then
  if test "x$cross_compiling" = "xyes" ; then
    BUILD_CFLAGS=
  else
    BUILD_CFLAGS=${CFLAGS}
  fi
fi
AC_SUBST(BUILD_CFLAGS)

if test "x${BUILD_LDFLAGS+set}" != "xset" ; then
  if test "x$cross_compiling" = "xyes" ; then
    BUILD_LDFLAGS=
  else
    BUILD_LDFLAGS=${LDFLAGS}
  fi
fi
AC_SUBST(BUILD_LDFLAGS)

# AC_C___ATTRIBUTE__

dnl
dnl Check if --version-script is supported by ld
dnl
AC_CACHE_CHECK(for .symver assembler directive, libc_cv_asm_symver_directive,
[cat > conftest.s <<EOF
${libc_cv_dot_text}
_sym:
.symver _sym,sym@VERS
EOF
if ${CC-cc} -c $ASFLAGS conftest.s 1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD; then
  libc_cv_asm_symver_directive=yes
else
  libc_cv_asm_symver_directive=no
fi
rm -f conftest*])
AC_CACHE_CHECK(for ld --version-script, libc_cv_ld_version_script_option, [dnl
if test $libc_cv_asm_symver_directive = yes; then
  cat > conftest.s <<EOF
${libc_cv_dot_text}
_sym:
.symver _sym,sym@VERS
EOF
  cat > conftest.map <<EOF
VERS_1 {
        global: sym;
};

VERS_2 {
        global: sym;
} VERS_1;
EOF
  if ${CC-cc} -c $ASFLAGS conftest.s 1>&AS_MESSAGE_LOG_FD 2>&AS_MESSAGE_LOG_FD;
then
    if AC_TRY_COMMAND([${CC-cc} $CFLAGS $LDFLAGS -shared
                                -o conftest.so conftest.o
                                -nostartfiles -nostdlib
                                -Wl,--version-script,conftest.map
                       1>&AS_MESSAGE_LOG_FD]);
    then
      libc_cv_ld_version_script_option=yes
    else
      libc_cv_ld_version_script_option=no
    fi
  else
    libc_cv_ld_version_script_option=no
  fi
else
  libc_cv_ld_version_script_option=no
fi
rm -f conftest*])
AM_CONDITIONAL([HAVE_VERSIONING],
	[test "$libc_cv_ld_version_script_option" = "yes"])

dnl
dnl check for -fPIE/-pie support
dnl
dnl icc handles -fpie as -fp without error, so blacklist icc
dnl
AC_ARG_ENABLE(pie,AS_HELP_STRING([--disable-pie],
                        [disable position-independent executeables (PIE)]),
        USE_PIE=$enableval, USE_PIE=yes)

AC_CACHE_CHECK(for -fpie, libc_cv_fpie, [dnl
  cat > conftest.c <<EOF
int foo;
main () { return 0;}
EOF
  if test "$USE_PIE" = "yes" -a "$CC" != "icc" &&
        AC_TRY_COMMAND([${CC-cc} $CFLAGS $CPPFLAGS $LDFLAGS -pie -fpie
                              -o conftest conftest.c 1>&AS_MESSAGE_LOG_FD])
  then
    libc_cv_fpie=yes
    PIE_CFLAGS="-fpie"
    PIE_LDFLAGS="-pie"
  else
    libc_cv_fpie=no
    PIE_CFLAGS=""
    PIE_LDFLAGS=""
  fi
  rm -f conftest*])
AC_SUBST(libc_cv_fpie)
AC_SUBST(PIE_CFLAGS)
AC_SUBST(PIE_LDFLAGS)


dnl dnl
dnl dnl options and defaults
dnl dnl

dnl AC_ARG_ENABLE([prelude],
dnl 	AS_HELP_STRING([--disable-prelude],[do not use prelude]),
dnl 	WITH_PRELUDE=$enableval, WITH_PRELUDE=yes)
dnl if test "$WITH_PRELUDE" == "yes" ; then
dnl   AM_PATH_LIBPRELUDE([0.9.0])
dnl   if test "$LIBPRELUDE_CONFIG" != "no" ; then
dnl     LIBPRELUDE_CFLAGS="$LIBPRELUDE_CFLAGS -DPRELUDE=1"
dnl   fi
dnl fi

dnl lots of debugging information goes to /var/run/pam-debug.log
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug],[specify you are building with debugging on]))

if test x"$enable_debug" = x"yes" ; then
   AC_DEFINE([PAM_DEBUG],,
		[lots of stuff gets written to /var/run/pam-debug.log])
fi

dnl AC_ARG_ENABLE(securedir,
dnl 	AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@]),
dnl 	SECUREDIR=$enableval, SECUREDIR=$libdir/security)
dnl AC_SUBST(SECUREDIR)

dnl AC_ARG_ENABLE([isadir],
dnl 	AS_HELP_STRING([--enable-isadir=DIR],[path to arch-specific module files @<:@default=../../(basename of $libdir)/security@:>@]),
dnl ISA=$enableval,
dnl ISA=../../`basename $libdir`/security)
dnl unset mylibdirbase
dnl AC_DEFINE_UNQUOTED(_PAM_ISA,"$ISA",[Define to the path, relative to SECUREDIR, where PAMs specific to this architecture can be found.])
dnl AC_MSG_RESULT([Defining \$ISA to "$ISA"])

dnl AC_ARG_ENABLE(sconfigdir,
dnl 	AS_HELP_STRING([--enable-sconfigdir=DIR],[path to module conf files @<:@default=$sysconfdir/security@:>@]),
dnl 	SCONFIGDIR=$enableval, SCONFIGDIR=$sysconfdir/security)
dnl AC_SUBST(SCONFIGDIR)

AC_ARG_ENABLE(pamlocking,
	AS_HELP_STRING([--enable-pamlocking],[configure libpam to observe a global authentication lock]))

if test x"$enable_pamlocking" = "xyes"; then
   AC_DEFINE([PAM_LOCKING],,
	[libpam should observe a global authentication lock])
fi

AC_ARG_ENABLE(read-both-confs,
	AS_HELP_STRING([--enable-read-both-confs],[read both /etc/pam.d and /etc/pam.conf files]))

if test x"$enable_read_both_confs" = "xyes"; then
   AC_DEFINE([PAM_READ_BOTH_CONFS],,
		[read both /etc/pam.d and /etc/pam.conf files])
fi

dnl AC_ARG_ENABLE([lckpwdf],
dnl 	AS_HELP_STRING([--disable-lckpwdf],[do not use the lckpwdf function]),
dnl 	WITH_LCKPWDF=$enableval, WITH_LCKPWDF=yes)
dnl if test "$WITH_LCKPWDF" == "yes" ; then
dnl     AC_DEFINE([USE_LCKPWDF], 1,
dnl 		[Define to 1 if the lckpwdf function should be used])
dnl fi

AC_CHECK_HEADERS(paths.h)
AC_ARG_WITH(mailspool,
[  --with-mailspool        path to mail spool directory
                          [default _PATH_MAILDIR if defined in paths.h, otherwise /var/spool/mail]],
with_mailspool=${withval})
if test x$with_mailspool != x ; then
	pam_mail_spool="\"$with_mailspool\""
else
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <paths.h>
int main() {
#ifdef _PATH_MAILDIR
exit(0);
#else
exit(1);
#endif
}]])],[pam_mail_spool="_PATH_MAILDIR"],[pam_mail_spool="\"/var/spool/mail\""],[pam_mail_spool="\"/var/spool/mail\""])
fi
AC_DEFINE_UNQUOTED(PAM_PATH_MAILDIR, $pam_mail_spool,
	[Path where mails are stored])

AC_ARG_WITH(xauth,
[  --with-xauth            additional path to check for xauth when it is called from pam_xauth
                          [added to the default of /usr/X11R6/bin/xauth, /usr/bin/xauth, /usr/bin/X11/xauth]],
pam_xauth_path=${withval})
if test x$with_xauth == x ; then
	AC_PATH_PROG(pam_xauth_path, xauth)
dnl There is no sense in adding the first default path
	if test x$pam_xauth_path == x/usr/X11R6/bin/xauth ; then
		unset pam_xauth_path
	fi
fi

if test x$pam_xauth_path != x ; then
	AC_DEFINE_UNQUOTED(PAM_PATH_XAUTH, "$pam_xauth_path",
	[Additional path of xauth executable])
fi

dnl Checks for the existence of libdl - on BSD and Tru64 its part of libc
AC_CHECK_LIB([dl], [dlopen], LIBDL="-ldl", LIBDL="")
AC_SUBST(LIBDL)

# Check for cracklib
AC_ARG_ENABLE([cracklib],
        AS_HELP_STRING([--disable-cracklib],[do not use cracklib]),
        WITH_CRACKLIB=$enableval, WITH_CRACKLIB=yes)
if test x"$WITH_CRACKLIB" != xno ; then
        AC_CHECK_HEADERS([crack.h],
              AC_CHECK_LIB([crack], [FascistCheck], LIBCRACK="-lcrack", LIBCRACK=""))
else
	LIBCRACK=""
fi
if test -n "$LIBCRACK"; then
	AC_DEFINE([HAVE_LIBCRACK], [1], [Define to 1 if you have cracklib.])
fi
AC_SUBST(LIBCRACK)
AM_CONDITIONAL([HAVE_LIBCRACK], [test -n "$LIBCRACK"])


# Checks for libraries.
AC_ARG_WITH([randomdev], AS_HELP_STRING([--with-randomdev=(<path>|yes|no)],[use specified random device instead of /dev/urandom or 'no' to disable]), opt_randomdev=$withval)
if test "$opt_randomdev" = yes -o -z "$opt_randomdev"; then
       opt_randomdev="/dev/urandom"
elif test "$opt_randomdev" = no; then
       opt_randomdev=
fi
if test -n "$opt_randomdev"; then
       AC_DEFINE_UNQUOTED(PAM_PATH_RANDOMDEV, "$opt_randomdev", [Random device path.])
fi

dnl Look for Linux Auditing library - see documentation
AC_ARG_ENABLE([audit],
        AS_HELP_STRING([--disable-audit],[do not enable audit support]),
        WITH_LIBAUDIT=$enableval, WITH_LIBAUDIT=yes)
if test x"$WITH_LIBAUDIT" != xno ; then
        AC_CHECK_HEADER([libaudit.h],
              [AC_CHECK_LIB(audit, audit_log_acct_message, LIBAUDIT=-laudit, LIBAUDIT="")
	       AC_CHECK_TYPE([struct audit_tty_status],
		             [HAVE_AUDIT_TTY_STATUS=yes],
			     [HAVE_AUDIT_TTY_STATUS=""],
			     [#include <libaudit.h>])]
        )
        if test ! -z "$LIBAUDIT" -a "$ac_cv_header_libaudit_h" != "no" ; then
            AC_DEFINE([HAVE_LIBAUDIT], 1, [Define to 1 if audit support should be compiled in.])
        fi
        if test ! -z "$HAVE_AUDIT_TTY_STATUS" ; then
            AC_DEFINE([HAVE_AUDIT_TTY_STATUS], 1, [Define to 1 if struct audit_tty_status exists.])

            AC_CHECK_MEMBERS([struct audit_tty_status.log_passwd], [],
                            AC_MSG_WARN([audit_tty_status.log_passwd is not available.  The log_passwd option is disabled.]),
                            [[#include <libaudit.h>]])
        fi
else
	LIBAUDIT=""
fi
AC_SUBST(LIBAUDIT)
AM_CONDITIONAL([HAVE_AUDIT_TTY_STATUS],
	       [test "x$HAVE_AUDIT_TTY_STATUS" = xyes])

AC_CHECK_HEADERS(xcrypt.h crypt.h)
AS_IF([test "x$ac_cv_header_xcrypt_h" = "xyes"],
  [crypt_libs="xcrypt crypt"],
  [crypt_libs="crypt"])

BACKUP_LIBS=$LIBS
AC_SEARCH_LIBS([crypt],[$crypt_libs], LIBCRYPT="-l$ac_lib", LIBCRYPT="")
AC_CHECK_FUNCS(crypt_r crypt_gensalt_r)
LIBS=$BACKUP_LIBS
AC_SUBST(LIBCRYPT)
if test "$LIBCRYPT" = "-lxcrypt" -a "$ac_cv_header_xcrypt_h" = "yes" ; then
	AC_DEFINE([HAVE_LIBXCRYPT], 1, [Define to 1 if xcrypt support should be compiled in.])
fi

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h malloc.h shadow.h stdlib.h string.h sys/time.h syslog.h unistd.h utmp.h])

AM_CONDITIONAL(ENABLE_REGENERATE_MAN, test x$enable_docu != xno)
AM_CONDITIONAL(ENABLE_GENERATE_PDF, test ! -z "$FO2PDF")

# Checks for typedefs, structures, and compiler characteristics.

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T

AH_BOTTOM([#ifdef ENABLE_NLS
#include <libintl.h>
#define _(msgid) dgettext(PACKAGE, msgid)
#define N_(msgid) msgid
#else
#define _(msgid) (msgid)
#define N_(msgid) msgid
#endif /* ENABLE_NLS */])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 getdelim gettimeofday memchr memset stpcpy strcasecmp strchr strdup strncasecmp strpbrk strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
