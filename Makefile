full: chkpw

chkpw: chkpw.c
	gcc -o chkpw chkpw.c -lcrypt
	sudo chown --reference=/sbin/unix_chkpwd chkpw
	sudo chmod --reference=/sbin/unix_chkpwd chkpw

pam_unix: pam_unix.c
	gcc -fPIC -c pam_unix.c
	gcc -shared -o pam_unix.so pam_unix.o -lpam

pam_opendirectory: pam_opendirectory.o fix_pw.o
	gcc -shared -o pam_opendirectory.so pam_opendirectory.o fix_pw.o -F/System/Library/Frameworks/ -framework CoreFoundation -framework OpenDirectory -lpam
pam_opendirectory.o: pam_opendirectory.c
	gcc -fPIC -c pam_opendirectory.c
pam_typopw: pam_typopw.o fix_pw.o
	gcc -shared -o pam_typopw.so pam_typopw.o fix_pw.o -lpam -lcrypt
pam_typopw.o: pam_typopw.c
	gcc -fPIC -c pam_typopw.c
fix_pw.o: fix_pw.c fix_pw.h
	gcc -fPIC -c fix_pw.c
clean:
	rm -rf pam_typopw.o pam_typopw.so fix_pw.o test.o


test: test.c fix_pw.o test_fix_pw.c pam_typopw
	g++ -o test_pam -lpam pam_typow.so
