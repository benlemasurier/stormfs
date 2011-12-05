bin_PROGRAMS = stormfs

stormfs_SOURCES = cache.c curl.c stormfs.c
stormfs_LDADD = $(LIBS) $(LIBGCRYPT_LIBS)
stormfs_CFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=26 -D_FILE_OFFSET_BITS=64 $(DEPS_CFLAGS)
stormfs_LDFLAGS = $(DEPS_LIBS)
