SUBDIRS = src

# additional flags to be passed to aclocal when invoked at make time.
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

dist_noinst_SCRIPTS = autogen.sh

dist-hook:
	rm -rf `find $(distdir)/doc -type d -name .svn`
