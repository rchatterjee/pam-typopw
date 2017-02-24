CFLAGS ?= -O2 -g -Wall -Wformat-security
CFLAGS += -fPIC -fvisibility=hidden
CFLAGS += -I/usr/include/security/ -I/usr/include/python2.7/ -I../
LDFLAGS += -Wl,-x -shared
LDLIBS = -lpython2.7 -lpam

all: pam_typtop.so run_as_root

pam_typtop.so: pam_typtop.o
	$(CC) $(LDFLAGS) $(LIBOBJ) $(LDLIBS) pam_typtop.o -o $@

run_as_root: ../run_as_root.c
	$(CC) -O2 -g -Wall -Wformat-security -I/usr/include/python2.7/ ../run_as_root.c -o $@ $(LDLIBS)

install: pam_typtop.so run_as_root
	# ./uninstall.sh
	./install.sh

uninstall:
	./uninstall.sh

clean:
	$(RM) *.o *.so run_as_root

.PHONY: install uninstall clean
