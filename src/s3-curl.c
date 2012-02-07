/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "stormfs.h"
#include "curl.h"
#include "s3-curl.h"

struct s3_curl {
  struct stormfs *stormfs;
} s3_curl;

HTTP_HEADER *
acl_header(const char *acl)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-acl");
  h->value = strdup(acl);

  return h;
}

HTTP_HEADER *
content_header(const char *type)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("Content-Type");
  if(type == NULL)
    h->value = strdup(DEFAULT_MIME_TYPE);
  else
    h->value = strdup(type);

  return h;
}

HTTP_HEADER *
copy_meta_header()
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("COPY");

  return h;
}

HTTP_HEADER *
copy_source_header(const char *path)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-copy-source");
  h->value = get_resource(path);

  return h;
}

HTTP_HEADER *
copy_source_range_header(off_t first, off_t last)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-copy-source-range");
  if(asprintf(&h->value, "bytes=%jd-%jd", 
        (intmax_t) first, (intmax_t) last) == -1)
    fprintf(stderr, "unable to allocate memory\n");

  return h;
}

HTTP_HEADER *
ctime_header(time_t t)
{
  char *s = time_to_s(t);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-meta-ctime");
  h->value = s;

  return h;
}

HTTP_HEADER *
encryption_header(void)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-server-side-encryption");
  h->value = strdup("AES256");

  return h;
}

HTTP_HEADER *
expires_header(const char *expires)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("Expires");
  h->value = strdup(expires);

  return h;
}

HTTP_HEADER *
gid_header(gid_t gid)
{
  char *s = gid_to_s(gid);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-gid");
  h->value = s;

  return h;
}

HTTP_HEADER *
mode_header(mode_t mode)
{
  char *s = mode_to_s(mode);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-mode");
  h->value = s;

  return h;
}

HTTP_HEADER *
mtime_header(time_t t)
{
  char *s = time_to_s(t);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-meta-mtime");
  h->value = s;

  return h;
}

HTTP_HEADER *
rdev_header(dev_t rdev)
{
  char *s = rdev_to_s(rdev);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-rdev");
  h->value = s;

  return h;
}

HTTP_HEADER *
replace_header()
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-metadata-directive");
  h->value = strdup("REPLACE");

  return h;
}

HTTP_HEADER *
storage_header(const char *class)
{
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key = strdup("x-amz-storage-class");
  h->value = strdup(class);

  return h;
}

HTTP_HEADER *
uid_header(uid_t uid)
{
  char *s = uid_to_s(uid);
  HTTP_HEADER *h = g_new0(HTTP_HEADER, 1);

  h->key   = strdup("x-amz-meta-uid");
  h->value = s;

  return h;
}

char *
get_resource(const char *path)
{
  int path_len = strlen(path);
  int bucket_len = strlen(s3_curl.stormfs->bucket);
  char *resource = g_malloc0(sizeof(char) * path_len + bucket_len + 2);

  strncpy(resource, "/", 1);
  strncat(resource, s3_curl.stormfs->bucket, bucket_len);
  strncat(resource, path, path_len);

  return resource;
}

int
s3_curl_init(struct stormfs *stormfs)
{
  s3_curl.stormfs = stormfs;

  return stormfs_curl_init(stormfs);
}

void
s3_curl_destroy(void)
{
  stormfs_curl_destroy();
}
