# CC=clang

all: pam_opendirectory_typo.so

pam_opendirectory_typo.so: pam_opendirectory.c
	${CC} -fPIC -lpam -flat_namespace -o pam_opendirectory_typo.so pam_opendirectory.c

clean:
	rm -rf pam_opendirectory_typo.so
