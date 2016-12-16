
CLEANFILES = *~

AUTOMAKE_OPTIONS = foreign
extra_cflags=$$(pkg-config --cflags python)
extra_libs=$$(pkg-config --libs python)

AM_CFLAGS = -DCHKPWD_HELPER=\"$(sbindir)/unix_chkpwd\" \
	-DUPDATE_HELPER=\"$(sbindir)/unix_update\" \
	$(NIS_CFLAGS)

AM_LDFLAGS = $(extra_libs)
# if HAVE_LIBSELINUX
#    AM_CFLAGS += -D"WITH_SELINUX"
# endif

sbin_PROGRAMS = unix_chkpwd unix_chkpwd_orig

unix_chkpwd_SOURCES = unix_chkpwd.c md5_good.c md5_broken.c bigcrypt.c \
	passverify.c
unix_chkpwd_CFLAGS = $(AM_CFLAGS) -DHELPER_COMPILE=\"unix_chkpwd\"
unix_chkpwd_LDFLAGS = 
unix_chkpwd_LDADD = @LIBCRYPT@ @LIBAUDIT@

unix_chkpwd_orig_SOURCES = unix_chkpwd_orig.c md5_good.c md5_broken.c bigcrypt.c \
	passverify.c
unix_chkpwd_orig_CFLAGS = $(AM_CFLAGS) -DHELPER_COMPILE=\"unix_chkpwd\"
unix_chkpwd_orig_LDFLAGS = 
unix_chkpwd_orig_LDADD = @LIBCRYPT@ @LIBAUDIT@


# bin_PROGRAMS = typtop
# typtop_SOURCES = typtops.c
# typtop_CFLAGS = $(extra_cflags) 
# typtop_LDFLAGS = $(extra_libs)
# typtop_LDADD = 


install-exec-hook:
	chgrp shadow /sbin/unix_chkpwd_orig;  chmod g+s /sbin/unix_chkpwd_orig
	chgrp shadow /sbin/unix_chkpwd;  chmod g+s /sbin/unix_chkpwd
	chgrp shadow /usr/local/bin/typtop; chmod g+s /usr/locl/bin/typtop
