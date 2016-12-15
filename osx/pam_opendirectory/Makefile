# CC=clang

all: pam_opendirectory_typo.so run_as_root

run_as_root: run_as_root.c
	${CC} run_as_root.c -o run_as_root

pam_opendirectory_typo.so: pam_opendirectory_typo.c
	${CC} -lpam -fPIC -bundle -flat_namespace -o pam_opendirectory_typo.so pam_opendirectory_typo.c -F/System/Library/PrivateFrameworks -framework CoreFoundation -framework OpenDirectory

install:
	sudo mkdir -p /usr/local/lib/security
	sudo cp pam_opendirectory_typo.so /usr/local/lib/security/
	sudo chmod u+s /usr/local/lib/security/pam_opendirectory_typo.so
	for f in /etc/pam.d/{screensaver,su} ; do \
		if [ ! -e $$f ]; then continue ; fi ;\
		if [ "$$(grep pam_opendirectory_typo $$f)" != "" ]; then \
			echo "Already instaled ignoring..."; \
		else \
			sudo sed -i '.bak' 's/^auth\(.*\)pam_opendirectory.so/auth\1\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/g' $$f ;\
		fi ; \
	done
	sudo touch /var/log/typtop.log && sudo chmod o+w /var/log/typtop.log
	sudo cp run_as_root /usr/local/bin/typtop
	sudo chmod u+s /usr/local/bin/typtop

uninstall:
	for f in /etc/pam.d/{screensaver,su} ; do \
		if [ ! -e $$f.bak ]; then continue ; fi ;\
		if [ "$$(grep pam_opendirectory_typo $$f.bak)" != "" ] ; then \
			echo "Backup file is wrong. Removing all pam_opendirectory_typo with pam_opendirectory. Checkout the webpage" ; \
			sudo sed -i '' 's/^auth\(.*\)\/usr\/local\/lib\/security\/pam_opendirectory_typo.so/auth\1pam_opendirectory.so/g' $$f ; \
		else \
			sudo mv $$f.bak $$f; \
		fi ; \
	done

clean:
	rm -rf pam_opendirectory_typo.so run_as_root
