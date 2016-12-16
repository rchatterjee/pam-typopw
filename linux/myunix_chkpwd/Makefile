
finbin = /sbin/unix_chkpwd

all: chkpw
	chown root:shadow chkpw
	chmod g+s chkpw

chkpw: chkpw.c
	gcc chkpw.c -o chkpw -lcrypt

clean:
	rm -rf chkpw

install:
	mv $(finbin) $(finbin).bak
	cp chkpw $(finbin)
	chown root:shadow $(finbin)
	chmod g+s $(finbin)

unistall:
	mv $(finbin).bak $(finbin)
	chown root:shadow $(finbin)
	chmod g+s $(finbin)
