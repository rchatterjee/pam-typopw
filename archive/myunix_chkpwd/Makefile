
finbin = /sbin/unix_chkpwd
lib_root = /usr/local
script_root = $(lib_root)/bin
db_root = $(lib_root)/etc/typtop.d
authorized_execs = {su,sudo,login}

all: chkpw chkpw_orig run_as_root

run_as_root: run_as_root.c
	gcc run_as_root.c -o run_as_root

chkpw: chkpw.c
	gcc chkpw.c -o chkpw -lcrypt

chkpw_orig: chkpw_orig.c
	gcc chkpw_orig.c -o chkpw_orig -lcrypt

clean:
	rm -rf chkpw

install: all
	if [ ! -e $(finbin).bak ]; then \
		mv $(finbin) $(finbin).bak; \
	fi
	mkdir -p $(db_root)
	chown -R root:shadow $(db_root)
	chmod ug+w $(db_root)
	cp chkpw $(finbin)
	cp chkpw $(finbin).orig
	shasum -a 256 $(finbin) > $(db_root)/authorized_caller
	chown root:shadow $(finbin) $(finbin).orig
	chmod ug+s $(finbin) $(finbin).orig
	touch /var/log/typtop.log && chmod o+w /var/log/typtop.log
	cp run_as_root $(script_root)/typtop
	chown root:shadow $(script_root)/typtop
	chmod g+s $(script_root)/typtop

unistall:
	mv $(finbin).bak $(finbin)
	chown root:shadow $(finbin)
	chmod g+s $(finbin)
