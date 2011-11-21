/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef stormfs_curl_H
#define stormfs_curl_H

#define FIVE_GB 5368709120LL

typedef struct {
  char *key;
  char *value;
} HTTP_HEADER;

HTTP_HEADER *copy_source_header(const char *path);
HTTP_HEADER *copy_meta_header();
HTTP_HEADER *gid_header(gid_t gid);
HTTP_HEADER *uid_header(uid_t uid);
HTTP_HEADER *mode_header(mode_t mode);
HTTP_HEADER *mtime_header(time_t t);
HTTP_HEADER *content_header(const char *type);
HTTP_HEADER *replace_header();
GList *strip_header(GList *headers, const char *key);
void free_headers(HTTP_HEADER *h);

int stormfs_curl_delete(const char *path);
void stormfs_curl_destroy();
int stormfs_curl_get(const char *path, char **data);
int stormfs_curl_get_file(const char *path, FILE *f);
int stormfs_curl_head(const char *path, GList **meta);
int stormfs_curl_init(const char *bucket, const char *url);
int stormfs_curl_list_bucket(const char *path, char **xml);
int stormfs_curl_put_headers(const char *path, GList *headers);
int stormfs_curl_rename(const char *from, const char *to);
int stormfs_curl_set_auth(const char *access_key, const char *secret_key);
int stormfs_curl_upload(const char *path, GList *headers, int fd);
int stormfs_curl_verify_ssl(int verify);

#endif // stormfs_curl_H

