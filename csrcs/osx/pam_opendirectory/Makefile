# CC=clang
root = /usr/local
db_root = $(root)/etc/typtop.d
script_root = $(root)/bin/
lib_root = $(root)/lib
authorized_execs = {su,screensaver}
LDLIBS = -lpython2.7 -lpam

all: pam_opendirectory_typo.so run_as_root
	cp ./pam_opendirectory_typo.so ./run_as_root ../prebuilt/

run_as_root: ../../run_as_root.c
	$(CC) -O2 -g -Wall -Wformat-security -I/usr/include/python2.7/ ../../run_as_root.c -o $@ $(LDLIBS)

pam_opendirectory_typo.so: pam_opendirectory_typo.c
	${CC} -lpam -fPIC -bundle -flat_namespace -o pam_opendirectory_typo.so pam_opendirectory_typo.c -DDEBUG=1 -F/System/Library/PrivateFrameworks -framework CoreFoundation -framework OpenDirectory -I../../

typtops.out: typtops.c
	${CC} -O3 -I /usr/include/python2.7/ -o typtops.out typtops.c -lpython2.7 -lpthread -lm -lutil -ldl -lssl

typtops.c: ../../typtops.py
	cython --embed -o typtops.c ../../typtops.py

install: all
	../prebuilt/install.sh

uninstall:
	../prebuilt/uninstall.sh

clean:
	rm -rf pam_opendirectory_typo.so run_as_root typtops
