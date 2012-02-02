bin_PROGRAMS = stormfs

stormfs_SOURCES = proxy.c proxy.h s3.h s3.c curl.h curl.c stormfs.h stormfs.c
stormfs_CFLAGS = -D_REENTRANT \
                 -DFUSE_USE_VERSION=26 \
                 -D_FILE_OFFSET_BITS=64 \
                 -DSYSCONFDIR=\"${sysconfdir}\" \
                 ${FUSE_CFLAGS} \
                 ${CURL_CFLAGS} \
                 ${GLIB_CFLAGS} \
                 ${GTHREAD_CFLAGS}
stormfs_LDADD = ${LIBS} \
                ${FUSE_LIBS} \
                ${CURL_LIBS} \
                ${GLIB_LIBS} \
                ${GTHREAD_LIBS}
