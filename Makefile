full: pam_typopw

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
