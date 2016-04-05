full: pam_opendirectory

pam_opendirectory: pam_opendirectory.o fix_pw.o
	gcc -shared -o pam_opendirectory.so pam_opendirectory.o fix_pw.o -F/System/Library/Frameworks/ -framework CoreFoundation -framework OpenDirectory -lpam
pam_opendirectory.o: pam_opendirectory.c
	gcc -fPIC -c pam_opendirectory.c

pam_typopw: pam_typopw.o fix_pw.o
	gcc -shared -o pam_typopw.so pam_typopw.o fix_pw.o -lpam
pam_typopw.o: pam_typopw.c
	gcc -fPIC -c pam_typopw.c
fix_pw.o: fix_pw.c fix_pw.h
	gcc -fPIC -c fix_pw.c
clean:
	rm -rf pam_typopw.o pam_typopw.so fix_pw.o test.o


test: test.c fix_pw.o test_fix_pw.c pam_typopw
	g++ -o test_pam -lpam pam_typow.so
