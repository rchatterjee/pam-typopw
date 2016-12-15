# CC=clang

all: pam_opendirectory_typo.so run_as_root

run_as_root: run_as_root.c
	${CC} run_as_root.c -o run_as_root

pam_opendirectory_typo.so: pam_opendirectory_typo.c
	${CC} -lpam -fPIC -bundle -flat_namespace -o pam_opendirectory_typo.so pam_opendirectory_typo.c -F/System/Library/PrivateFrameworks -framework CoreFoundation -framework OpenDirectory

typtops: typtops.c
	${CC} -O3 -I /usr/include/python2.7/ -o typtops.out typtops.c -lpython2.7 -lpthread -lm -lutil -ldl -lssl
install:
	mkdir -p /usr/local/lib/security
	cp pam_opendirectory_typo.so /usr/local/lib/security/
	sed -i '' s/__recorded_digest__1/$(sha256sum /usr/local/lib/security/pam_opendirectory_typo.so)/g $(python -c "from typtop import validate_parent; validate_parent.__file__")
	for f in /etc/pam.d/{screensaver,su} ; do \
		if [ ! -e $$f ]; then continue ; fi ;\
		if [ "$$(grep pam_opendirectory_typo $$f)" != "" ]; then \
			echo "Already instaled ignoring..."; \
		else \
			sed -i '.bak' 's/^auth\(.*\)pam_opendirectory.so/auth\1\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/g' $$f ;\
		fi ; \
	done
	touch /var/log/typtop.log && chmod o+w /var/log/typtop.log
	# cp run_as_root /usr/local/bin/typtop
	cp typtops.out /usr/local/bin/typtop
	chmod u+s /usr/local/bin/typtop

uninstall:
	for f in /etc/pam.d/{screensaver,su} ; do \
		if [ ! -e $$f.bak ]; then continue ; fi ;\
		if [ "$$(grep pam_opendirectory_typo $$f.bak)" != "" ] ; then \
			echo "Backup file is wrong. Removing all pam_opendirectory_typo with pam_opendirectory. Checkout the webpage" ; \
			sed -i '' 's/^auth\(.*\)\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/auth\1pam_opendirectory.so/g' $$f ; \
		else \
			mv $$f.bak $$f; \
		fi ; \
	done

clean:
	rm -rf pam_opendirectory_typo.so run_as_root
