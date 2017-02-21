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
	./install.sh

uninstall:
	./uninstall.sh

clean:
	rm -rf pam_opendirectory_typo.so run_as_root typtops
