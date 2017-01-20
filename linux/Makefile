CFLAGS ?= -O2 -g -Wall -Wformat-security
CFLAGS += -fPIC -fvisibility=hidden
CFLAGS += -I/usr/include/security/ -I/usr/include/python2.7/
LDFLAGS += -Wl,-x -shared
LDLIBS = -lpython2.7 -lpam

all: pam_typtop.so

pam_typtop.so: pam_typtop.o
	$(CC) $(LDFLAGS) $(LIBOBJ) pam_typtop.o -o $@


install: pam_typtop.so
	./install.sh

uninstall:
	./uninstall.sh

clean:
	$(RM) *.o *.so

.PHONY: install uninstall clean