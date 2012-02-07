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
#include "s3.h"

struct s3 {
  struct stormfs *stormfs;
} s3;

static GList *
add_optional_headers(GList *headers)
{
  headers = add_header(headers, storage_header(s3.stormfs->storage_class));
  headers = add_header(headers, acl_header(s3.stormfs->acl));
  if(s3.stormfs->encryption)
    headers = add_header(headers, encryption_header());
  if(s3.stormfs->expires != NULL)
    headers = add_header(headers, expires_header(s3.stormfs->expires));

  return headers;
}

static GList *
add_file_to_list(GList *list, const char *path, struct stat *st)
{
  struct file *f = g_new0(struct file, 1);
  struct stat *stbuf = g_new0(struct stat, 1);

  f->path = strdup(path);
  f->name = strdup(basename(f->path));

  if(st != NULL)
    memcpy(stbuf, st, sizeof(struct stat));

  f->st = stbuf;

  return g_list_append(list, f);
}

static GList *
xml_to_files(const char *path, char *xml)
{
  char *start_p = NULL;
  GList *files = NULL;

  if(strstr(xml, "xml") == NULL)
    return files;

  if((start_p = strstr(xml, "<Key>")) != NULL)
    start_p += strlen("<Key>");

  while(start_p != NULL) {
    char *name;
    char *fullpath;
    char *end_p = strstr(start_p, "</Key>");

    name = g_strndup(start_p, end_p - start_p);
    fullpath = get_path(path, name);
    files = add_file_to_list(files, fullpath, NULL);
    free(name);
    free(fullpath);

    if((start_p = strstr(end_p, "<Key>")) != NULL)
      start_p += strlen("<Key>");
  }

  return files;
}

void
s3_destroy(void)
{
  s3_curl_destroy();
}

int
s3_getattr(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  if((result = s3_curl_head(path, &headers)) != 0) {
    free_headers(headers);
    return result;
  }

  result = headers_to_stat(headers, st);
  free_headers(headers);

  return result;
}

int
s3_getattr_multi(const char *path, GList *files)
{
  int result;
  GList *head = NULL, *next = NULL;
  result = s3_curl_head_multi(path, files);

  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;

    struct file *f = head->data;
    GList *headers = f->headers;
    struct stat *stbuf = f->st;
    if((result = headers_to_stat(headers, stbuf)) != 0)
      return result;

    if(S_ISREG(stbuf->st_mode))
      stbuf->st_blocks = get_blocks(stbuf->st_size);

    head = next;
  }

  return result;
}

int
s3_chmod(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, replace_header());
  headers = add_header(headers, copy_source_header(path));

  result = s3_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
s3_chown(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, replace_header());
  headers = add_header(headers, copy_source_header(path));

  result = s3_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
s3_create(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, content_header(get_mime_type(path)));
  headers = add_optional_headers(headers);

  result = s3_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
s3_init(struct stormfs *stormfs)
{
  s3.stormfs = stormfs;

  if(s3_curl_init(stormfs) != 0) {
    fprintf(stderr, "%s: unable to initialize libcurl\n", stormfs->progname);
    exit(EXIT_FAILURE);
  }

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

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, acl_header(s3.stormfs->acl));
  headers = add_header(headers, content_header("application/x-directory"));
  headers = add_optional_headers(headers);

  result = s3_curl_upload(path, headers, fd);
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

  headers = stat_to_headers(headers, st);
  headers = add_optional_headers(headers);

  result = s3_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
s3_open(const char *path, FILE *f)
{
  return stormfs_curl_get_file(path, f);
}

int
s3_readdir(const char *path, GList **files)
{
  int result;
  char *xml = NULL;

  if((result = s3_curl_list_bucket(path, &xml)) != 0) {
    free(xml);
    return -EIO;
  }

  *files = xml_to_files(path, xml);
  free(xml);

  return result;
}

int
s3_release(const char *path, int fd, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, content_header(get_mime_type(path)));
  headers = add_header(headers, mtime_header(time(NULL)));
  headers = add_optional_headers(headers);

  result = s3_curl_upload(path, headers, fd);

  free_headers(headers);

  return result;
}

static int
s3_rename_file(const char *from, const char *to, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);

  /* files >= 5GB must be renamed via the multipart interface */
  if(st->st_size < FIVE_GB) {
    headers = add_header(headers, copy_meta_header());
    headers = add_header(headers, copy_source_header(from));

    result = s3_curl_put(to, headers);
  } else {
    headers = add_header(headers, content_header(get_mime_type(from)));
    result  = copy_multipart(from, to, headers, st->st_size);
  }

  free_headers(headers);

  return stormfs_unlink(from);
}

static int
s3_rename_directory(const char *from, const char *to, struct stat *st)
{
  int result;
  char *xml = NULL, *start_p = NULL;

  result = s3_curl_list_bucket(from, &xml);
  if(result != 0) {
    free(xml);
    return -EIO;
  }

  if(strstr(xml, "xml") == NULL)
    return -EIO;

  if((start_p = strstr(xml, "<Key>")) != NULL)
    start_p += strlen("<Key>");

  while(start_p != NULL) {
    char *name, *tmp, *file_from, *file_to;
    char *end_p = strstr(start_p, "</Key>");
    struct stat stbuf;

    tmp = g_strndup(start_p, end_p - start_p);
    name = basename(tmp);
    file_from = get_path(from, name);
    file_to   = get_path(to, name);

    if((result = stormfs_getattr(file_from, &stbuf)) != 0)
      return -result;

    if(S_ISDIR(stbuf.st_mode)) {
      if((result = s3_rename_directory(file_from, file_to, &stbuf)) != 0)
        return result;
    } else {
      if((result = s3_rename_file(file_from, file_to, &stbuf)) != 0)
        return result;
    }

    free(tmp);
    free(file_to);
    free(file_from);

    if((start_p = strstr(end_p, "<Key>")) != NULL)
      start_p += strlen("<Key>");
  }

  free(xml);

  return s3_rename_file(from, to, st);
}

int
s3_rename(const char *from, const char *to, struct stat *st)
{
  int result;

  if(S_ISDIR(st->st_mode))
    result = s3_rename_directory(from, to, st);
  else
    result = s3_rename_file(from, to, st);

  return result;
}

int
s3_rmdir(const char *path)
{
  int result;
  char *xml = NULL;

  if((result = s3_curl_list_bucket(path, &xml)) != 0) {
    free(xml);
    return result;
  }

  if(strstr(xml, "ETag") != NULL)
    result = -ENOTEMPTY;

  free(xml);
  if(result != 0)
    return result;

  return stormfs_curl_delete(path);
}

int
s3_symlink(const char *from, const char *to, struct stat *st)
{
  int result, fd;
  GList *headers = NULL;

  if((fd = fileno(tmpfile())) == -1)
    return -errno;

  if(pwrite(fd, from, strlen(from), 0) == -1) {
    close(fd);
    return -errno;
  }

  headers = add_header(headers, mode_header(st->st_mode));
  headers = add_header(headers, mtime_header(st->st_mtime));

  result = s3_curl_upload(to, headers, fd);

  free_headers(headers);
  if(close(fd) != 0)
    return -errno;

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

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, replace_header());
  headers = add_header(headers, copy_source_header(path));

  result = s3_curl_put(path, headers);

  free_headers(headers);

  return result;
}
