SUBDIRS = src doc
EXTRA_DIST = debian doc

install-data-local:
	test -e $(DESTDIR)/etc/stormfs.conf || \
		$(INSTALL) -m 640 $(srcdir)/stormfs.conf.example $(DESTDIR)/etc/stormfs.conf

dist_noinst_SCRIPTS = autogen.sh

dist-hook:
	rm -rf `find $(distdir) -type d -name .git`
