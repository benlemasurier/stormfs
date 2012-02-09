/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "curl.h"

#ifndef cloudfiles_curl_H
#define cloudfiles_curl_H

HTTP_HEADER *cf_ctime_header(time_t t);
HTTP_HEADER *cf_expires_header(const char *expires);
HTTP_HEADER *cf_gid_header(gid_t gid);
HTTP_HEADER *cf_mode_header(mode_t mode);
HTTP_HEADER *cf_mtime_header(time_t t);
HTTP_HEADER *cf_rdev_header(dev_t rdev);
HTTP_HEADER *cf_uid_header(uid_t uid);

int  cloudfiles_curl_delete(const char *path);
void cloudfiles_curl_destroy(void);
int  cloudfiles_curl_get_file(const char *path, FILE *f);
int  cloudfiles_curl_head(const char *path, GList **headers);
int  cloudfiles_curl_head_multi(const char *path, GList *files);
int  cloudfiles_curl_init(struct stormfs *stormfs);
int  cloudfiles_curl_list_objects(const char *path, char **data);
int  cloudfiles_curl_put(const char *path, GList *headers);
int  cloudfiles_curl_upload(const char *path, GList *headers, int fd);

#endif // cloudfiles_curl_H
