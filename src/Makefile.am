bin_PROGRAMS = stormfs

stormfs_SOURCES = curl.h curl.c stormfs.h stormfs.c
stormfs_LDADD = $(LIBS) $(LIBGCRYPT_LIBS)
stormfs_CFLAGS = -D_REENTRANT -DFUSE_USE_VERSION=26 -D_FILE_OFFSET_BITS=64 $(STORMFS_CFLAGS)
stormfs_LDFLAGS = $(STORMFS_LIBS)
