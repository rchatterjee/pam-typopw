if [ ! -e /sbin/unix_chkpwd.bak ]; then \
		mv /sbin/unix_chkpwd /sbin/unix_chkpwd.bak; \
	fi
mkdir -p /usr/local/etc/typtop.d
for tf in {su,sudo,login}; do \
		f=$(/usr/bin/which $tf); \
		if [ ! -z $f ]; then \
			shasum -a 256 $f ;\
		fi \
	done > /usr/local/etc/typtop.d/authorized_caller; \
	cp chkpw /sbin/unix_chkpwd
chown root:shadow /sbin/unix_chkpwd
chmod g+s /sbin/unix_chkpwd
touch /var/log/typtop.log && chmod o+w /var/log/typtop.log
cp run_as_root /usr/local/bin/typtop
chown root:shadow /usr/local/bin/typtop
chmod g+s /usr/local/bin/typtop
