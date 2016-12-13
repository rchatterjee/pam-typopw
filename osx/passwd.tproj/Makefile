# CC=clang

all: pam_opendirectory_typo.so

pam_opendirectory_typo.so: pam_opendirectory_typo.c
	${CC} -lpam -fPIC -bundle -flat_namespace -o pam_opendirectory_typo.so pam_opendirectory_typo.c -F/System/Library/PrivateFrameworks -framework CoreFoundation -framework OpenDirectory
	sudo mkdir -p /usr/local/lib/security
	sudo cp pam_opendirectory_typo.so /usr/local/lib/security/

clean:
	rm -rf pam_opendirectory_typo.so
