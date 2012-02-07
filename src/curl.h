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
#define DEFAULT_MIME_TYPE   "application/octet-stream"

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

struct post_data {
  const char *readptr;
  int remaining;
};

uid_t get_uid(const char *s);
gid_t get_gid(const char *s);
mode_t get_mode(const char *s);
time_t get_ctime(const char *s);
time_t get_mtime(const char *s);
dev_t get_rdev(const char *s);
off_t get_size(const char *s);

int  cmpstringp(const void *p1, const void *p2);
char *gid_to_s(gid_t gid);
char *header_to_s(HTTP_HEADER *h);
char *mode_to_s(mode_t mode);
char *rdev_to_s(dev_t rdev);
char *rfc2822_timestamp(void);
char *time_to_s(time_t t);
char *uid_to_s(uid_t uid);
char *url_encode(char *s);

HTTP_REQUEST *new_request(const char *path);
CURLM *get_multi_handle(void);

GList *add_header(GList *headers, HTTP_HEADER *h);
GList *strip_header(GList *headers, const char *key);
void free_header(HTTP_HEADER *h);
void free_headers(GList *headers);
GList *stat_to_headers(GList *headers, struct stat *st);

size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);
size_t write_memory_cb(void *ptr, size_t size, size_t nmemb, void *data);
int free_request(HTTP_REQUEST *request);
CURL *get_pooled_handle(const char *url);
void release_pooled_handle(CURL *c);
int stormfs_curl_easy_perform(CURL *c);

int stormfs_curl_delete(const char *path);
void stormfs_curl_destroy();
int stormfs_curl_get(const char *path, char **data);
int stormfs_curl_get_file(const char *path, FILE *f);
int stormfs_curl_head(const char *path, GList **meta);
int stormfs_curl_init(struct stormfs *stormfs);
int stormfs_curl_put(const char *path, GList *headers);
int stormfs_curl_rename(const char *from, const char *to);
int stormfs_curl_upload(const char *path, GList *headers, int fd);
int copy_multipart(const char *from, const char *to, GList *headers, off_t size);

#endif // stormfs_curl_H

