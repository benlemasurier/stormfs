/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include "stormfs.h"
#include "curl.h"
#include "s3.h"

struct s3 {
  struct stormfs *stormfs;
} s3;

int
s3_getattr(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  if((result = stormfs_curl_head(path, &headers)) != 0)
    return result;

  if((result = headers_to_stat(headers, st)) != 0)
    return result;

  free_headers(headers);

  return result;
}

int
s3_chmod(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, *st);
  headers = add_header(headers, replace_header());
  headers = add_header(headers, copy_source_header(path));

  result = stormfs_curl_put(path, headers);
  free_headers(headers);

  return result;
}

int
s3_chown(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, *st);
  headers = add_header(headers, replace_header());
  headers = add_header(headers, copy_source_header(path));

  result = stormfs_curl_put(path, headers);
  free_headers(headers);

  return result;
}

int
s3_create(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, *st);
  headers = add_header(headers, content_header(get_mime_type(path)));
  headers = add_optional_headers(headers);

  result = stormfs_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
s3_init(struct stormfs *stormfs)
{
  s3.stormfs = stormfs;

  return 0;
}

int
s3_mkdir(const char *path, struct stat *st)
{
  int result, fd;
  FILE *f;
  GList *headers = NULL;

  if((f = tmpfile()) == NULL)
    return -errno;

  if((fd = fileno(f)) == -1)
    return -errno;

  headers = stat_to_headers(headers, *st);
  headers = add_header(headers, acl_header(s3.stormfs->acl));
  headers = add_header(headers, content_header("application/x-directory"));
  headers = add_optional_headers(headers);

  result = stormfs_curl_upload(path, headers, fd);
  free_headers(headers);

  if(close(fd) != 0)
    return -errno;

  return result;
}

int
s3_mknod(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, *st);
  headers = add_optional_headers(headers);

  result = stormfs_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
s3_unlink(const char *path)
{
  return stormfs_curl_delete(path);
}

int
s3_utimens(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, *st);
  headers = add_header(headers, replace_header());
  headers = add_header(headers, copy_source_header(path));

  result = stormfs_curl_put(path, headers);
  free_headers(headers);

  return result;
}
