/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef s3_curl_H
#define s3_curl_H

HTTP_HEADER *acl_header(const char *acl);
HTTP_HEADER *content_header(const char *type);
HTTP_HEADER *copy_source_header(const char *path);
HTTP_HEADER *copy_source_range_header(off_t first, off_t last);
HTTP_HEADER *copy_meta_header();
HTTP_HEADER *ctime_header(time_t t);
HTTP_HEADER *expires_header(const char *expires);
HTTP_HEADER *encryption_header(void);
HTTP_HEADER *gid_header(gid_t gid);
HTTP_HEADER *mode_header(mode_t mode);
HTTP_HEADER *mtime_header(time_t t);
HTTP_HEADER *rdev_header(dev_t dev);
HTTP_HEADER *uid_header(uid_t uid);
HTTP_HEADER *replace_header();
HTTP_HEADER *storage_header(const char *class);

char *get_resource(const char *path);

void s3_curl_destroy(void);
int  s3_curl_init(struct stormfs *stormfs);

#endif // s3_curl_H
