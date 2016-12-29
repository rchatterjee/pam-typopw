# CC=clang
root = /usr/local
db_root = $(root)/etc/typtop.d
script_root = $(root)/bin/
lib_root = $(root)/lib
authorized_execs = {su,screensaver}
all: pam_opendirectory_typo.so run_as_root

run_as_root: run_as_root.c
	${CC} run_as_root.c -o run_as_root

pam_opendirectory_typo.so: pam_opendirectory_typo.c
	${CC} -lpam -fPIC -bundle -flat_namespace -o pam_opendirectory_typo.so pam_opendirectory_typo.c -DDEBUG=1 -F/System/Library/PrivateFrameworks -framework CoreFoundation -framework OpenDirectory

typtops.out: typtops.c
	${CC} -O3 -I /usr/include/python2.7/ -o typtops.out typtops.c -lpython2.7 -lpthread -lm -lutil -ldl -lssl

typtops.c: ../../typtops.py
	cython --embed -o typtops.c ../../typtops.py

install: all
	mkdir -p $(lib_root)/security/ $(db_root)
	cp pam_opendirectory_typo.so $(lib_root)/security/
	for f in /usr/bin/$(authorized_execs); do \
		if [ -e $$f ]; then shasum -a 256 $$f > $(db_root)/authorized_caller; fi \
	done
	for f in /etc/pam.d/$(authorized_execs) ; do \
		if [ ! -e $$f ]; then continue ; fi ;\
		if [ "$$(grep pam_opendirectory_typo $$f)" != "" ]; then \
			echo "Already instaled ignoring..."; \
		else \
			sed -i '.bak' 's/^auth\(.*\)pam_opendirectory.so/auth\1\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/g' $$f ;\
		fi ; \
	done
	touch /var/log/typtop.log && chmod o+w /var/log/typtop.log
	cp run_as_root $(script_root)/typtop
	chmod u+s $(script_root)/typtop

uninstall:
	for f in /etc/pam.d/$(authorized_execs) ; do \
		if [ ! -e $$f.bak ]; then continue ; fi ;\
		if [ "$$(grep pam_opendirectory_typo $$f.bak)" != "" ] ; then \
			echo "Backup file is wrong. Removing all pam_opendirectory_typo with pam_opendirectory. Checkout the webpage" ; \
			sed -i '' 's/^auth\(.*\)\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/auth\1pam_opendirectory.so/g' $$f ; \
		else \
			mv $$f.bak $$f; \
		fi ; \
	done

clean:
	rm -rf pam_opendirectory_typo.so run_as_root typtops
