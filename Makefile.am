SUBDIRS = src doc
EXTRA_DIST = debian doc conf

dist_sysconf_DATA = conf/stormfs.conf

dist_noinst_SCRIPTS = autogen.sh

install-exec-hook:
	chmod 640 $(DESTDIR)$(sysconfdir)/stormfs.conf

dist-hook:
	rm -rf `find $(distdir) -type d -name .git`
