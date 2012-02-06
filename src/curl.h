/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>

#ifndef stormfs_curl_H
#define stormfs_curl_H

#define FIVE_GB 5368709120LL

typedef struct {
  char *key;
  char *value;
} HTTP_HEADER;

typedef struct {
  char   *memory;
  size_t size;
} HTTP_RESPONSE;

typedef struct {
  CURL *c;
  char *url;
  char *path;
  bool done;
  HTTP_RESPONSE response;
  struct curl_slist *headers;
} HTTP_REQUEST;

uid_t get_uid(const char *s);
gid_t get_gid(const char *s);
mode_t get_mode(const char *s);
time_t get_ctime(const char *s);
time_t get_mtime(const char *s);
dev_t get_rdev(const char *s);
off_t get_size(const char *s);

char *gid_to_s(gid_t gid);
char *mode_to_s(mode_t mode);
char *rdev_to_s(dev_t rdev);
char *time_to_s(time_t t);
char *uid_to_s(uid_t uid);
char *url_encode(char *s);

HTTP_HEADER *acl_header(const char *acl);
HTTP_HEADER *content_header(const char *type);
HTTP_HEADER *copy_source_header(const char *path);
HTTP_HEADER *copy_source_range_header(off_t first, off_t last);
HTTP_HEADER *copy_meta_header();
HTTP_HEADER *ctime_header(time_t t);
HTTP_HEADER *expires_header(const char *expires);
HTTP_HEADER *encryption_header(void);
HTTP_HEADER *gid_header(gid_t gid);
HTTP_HEADER *rdev_header(dev_t dev);
HTTP_HEADER *uid_header(uid_t uid);
HTTP_HEADER *mode_header(mode_t mode);
HTTP_HEADER *mtime_header(time_t t);
HTTP_HEADER *replace_header();
HTTP_HEADER *storage_header(const char *class);
GList *add_header(GList *headers, HTTP_HEADER *h);
GList *strip_header(GList *headers, const char *key);
void free_header(HTTP_HEADER *h);
void free_headers(GList *headers);
GList *stat_to_headers(GList *headers, struct stat *st);
int headers_to_stat(GList *headers, struct stat *stbuf);

int stormfs_curl_delete(const char *path);
void stormfs_curl_destroy();
int stormfs_curl_get(const char *path, char **data);
int stormfs_curl_get_file(const char *path, FILE *f);
int stormfs_curl_head(const char *path, GList **meta);
int stormfs_curl_head_multi(const char *path, GList *files);
int stormfs_curl_init(struct stormfs *stormfs);
int stormfs_curl_list_bucket(const char *path, char **xml);
int stormfs_curl_put(const char *path, GList *headers);
int stormfs_curl_rename(const char *from, const char *to);
int stormfs_curl_upload(const char *path, GList *headers, int fd);
int copy_multipart(const char *from, const char *to, GList *headers, off_t size);

#endif // stormfs_curl_H

