bin_PROGRAMS = stormfs

stormfs_SOURCES = curl.h curl.c stormfs.h stormfs.c
stormfs_CFLAGS = -D_REENTRANT \
                 -DFUSE_USE_VERSION=26 \
                 -D_FILE_OFFSET_BITS=64 \
                 ${FUSE_CFLAGS} \
                 ${CURL_CFLAGS} \
                 ${GLIB_CFLAGS} \
                 ${GTHREAD_CFLAGS}
stormfs_LDADD = ${LIBS} \
                ${FUSE_LIBS} \
                ${CURL_LIBS} \
                ${GLIB_LIBS} \
                ${GTHREAD_LIBS}
