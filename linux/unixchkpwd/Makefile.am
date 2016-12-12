
CLEANFILES = *~

AUTOMAKE_OPTIONS = foreign
AM_CFLAGS = -DCHKPWD_HELPER=\"$(sbindir)/unix_chkpwd\" \
	-DUPDATE_HELPER=\"$(sbindir)/unix_update\" \
	$(NIS_CFLAGS)

# if HAVE_LIBSELINUX
#   AM_CFLAGS += -D"WITH_SELINUX"
# endif

sbin_PROGRAMS = unix_chkpwd

unix_chkpwd_SOURCES = unix_chkpwd.c md5_good.c md5_broken.c bigcrypt.c \
	passverify.c
unix_chkpwd_CFLAGS = $(AM_CFLAGS) -DHELPER_COMPILE=\"unix_chkpwd\"
unix_chkpwd_LDFLAGS = 
unix_chkpwd_LDADD = @LIBCRYPT@ @LIBAUDIT@
