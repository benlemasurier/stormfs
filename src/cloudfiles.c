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
#include "cloudfiles.h"
#include "cloudfiles-curl.h"
#include "curl.h"

struct cloudfiles {
  struct stormfs *stormfs;
} cloudfiles;

static GList *
stat_to_headers(GList *headers, struct stat *st)
{
  headers = add_header(headers, cf_gid_header(st->st_gid));
  headers = add_header(headers, cf_uid_header(st->st_uid));
  headers = add_header(headers, cf_mode_header(st->st_mode));
  headers = add_header(headers, cf_ctime_header(st->st_ctime));
  headers = add_header(headers, cf_mtime_header(st->st_mtime));
  headers = add_header(headers, cf_rdev_header(st->st_rdev));

  return headers;
}

static GList *
optional_headers(GList *headers)
{
  if(cloudfiles.stormfs->expires != NULL)
    headers = add_header(headers, expires_header(cloudfiles.stormfs->expires));

  return headers;
}

static int
headers_to_stat(GList *headers, struct stat *stbuf)
{
  GList *head = NULL,
        *next = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *h = head->data;

    // TODO: clean this up.
    if(strcmp(h->key, "X-Object-Meta-Uid") == 0)
      stbuf->st_uid = get_uid(h->value);
    else if(strcmp(h->key, "X-Object-Meta-Gid") == 0)
      stbuf->st_gid = get_gid(h->value);
    else if(strcmp(h->key, "X-Object-Meta-Ctime") == 0)
      stbuf->st_ctime = get_ctime(h->value);
    else if(strcmp(h->key, "X-Object-Meta-Mtime") == 0)
      stbuf->st_mtime = get_mtime(h->value);
    else if(strcmp(h->key, "X-Object-Meta-Rdev") == 0)
      stbuf->st_rdev = get_rdev(h->value);
    else if(strcmp(h->key, "Last-Modified") == 0 && stbuf->st_mtime == 0)
      stbuf->st_mtime = get_mtime(h->value);
    else if(strcmp(h->key, "X-Object-Meta-Mode") == 0)
      stbuf->st_mode = get_mode(h->value);
    else if(strcmp(h->key, "Content-Length") == 0)
      stbuf->st_size = get_size(h->value);
    else if(strcmp(h->key, "Content-Type") == 0)
      if(strstr(h->value, "x-directory"))
        stbuf->st_mode |= S_IFDIR;

    head = next;
  }

  return 0;
}

static GList *
objectlist_to_files(const char *path, char *xml)
{
  GList *files = NULL;
  char *tmp = strdup(xml), *p = NULL;

  p = strtok(tmp, "\r\n");
  while(p != NULL) {
    char *name;
    char *fullpath;

    name = strdup(p);
    fullpath = get_path(path, name);
    files = add_file_to_list(files, fullpath, NULL);
    free(name);
    free(fullpath);

    p = strtok(NULL, "\r\n");
  }

  free(tmp);

  return files;
}

void
cloudfiles_destroy(void)
{
}

int
cloudfiles_getattr(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  if((result = cloudfiles_curl_head(path, &headers)) != 0) {
    free_headers(headers);
    return result;
  }

  result = headers_to_stat(headers, st);
  free_headers(headers);

  return result;
}

int
cloudfiles_getattr_multi(const char *path, GList *files)
{
  int result;
  GList *head = NULL, *next = NULL;
  result = cloudfiles_curl_head_multi(path, files);

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
cloudfiles_chmod(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);

  result = cloudfiles_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
cloudfiles_chown(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);

  result = cloudfiles_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
cloudfiles_create(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, content_header(get_mime_type(path)));
  headers = optional_headers(headers);

  result = cloudfiles_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
cloudfiles_init(struct stormfs *stormfs)
{
  cloudfiles.stormfs = stormfs;

  if(cloudfiles_curl_init(stormfs) != 0) {
    fprintf(stderr, "%s: unable to initialize libcurl\n", stormfs->progname);
    exit(EXIT_FAILURE);
  }

  return 0;
}

int
cloudfiles_mkdir(const char *path, struct stat *st)
{
  int result, fd;
  FILE *f;
  GList *headers = NULL;

  if((f = tmpfile()) == NULL)
    return -errno;

  if((fd = fileno(f)) == -1)
    return -errno;

  headers = stat_to_headers(headers, st);
  headers = add_header(headers, content_header("application/x-directory"));
  headers = optional_headers(headers);

  result = cloudfiles_curl_upload(path, headers, fd);
  free_headers(headers);

  if(close(fd) != 0)
    return -errno;

  return result;
}

int
cloudfiles_mknod(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);
  headers = optional_headers(headers);

  result = cloudfiles_curl_put(path, headers);

  free_headers(headers);

  return result;
}

int
cloudfiles_open(const char *path, FILE *f)
{
  return -ENOTSUP;
}

int
cloudfiles_readdir(const char *path, GList **files)
{
  int result;
  char *data = NULL;

  if((result = cloudfiles_curl_list_objects(path, &data)) != 0) {
    free(data);
    return -EIO;
  }

  *files = objectlist_to_files(path, data);
  free(data);

  return result;
}

int
cloudfiles_release(const char *path, int fd, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_rename(const char *from, const char *to, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_rmdir(const char *path)
{
  return -ENOTSUP;
}

int
cloudfiles_symlink(const char *from, const char *to, struct stat *st)
{
  int result, fd;
  GList *headers = NULL;

  if((fd = fileno(tmpfile())) == -1)
    return -errno;

  if(pwrite(fd, from, strlen(from), 0) == -1) {
    close(fd);
    return -errno;
  }

  headers = add_header(headers, cf_mode_header(st->st_mode));
  headers = add_header(headers, cf_mtime_header(st->st_mtime));

  result = cloudfiles_curl_upload(to, headers, fd);

  free_headers(headers);
  if(close(fd) != 0)
    return -errno;

  return result;
}

int
cloudfiles_unlink(const char *path)
{
  return cloudfiles_curl_delete(path);
}

int
cloudfiles_utimens(const char *path, struct stat *st)
{
  int result;
  GList *headers = NULL;

  headers = stat_to_headers(headers, st);

  result = cloudfiles_curl_put(path, headers);

  free_headers(headers);

  return result;
}
