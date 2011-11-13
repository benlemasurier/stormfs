/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define FUSE_USE_VERSION 26
#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <fuse.h>
#include <glib.h>
#include "stormfs.h"
#include "stormfs_curl.h"

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_FOREGROUND,
};

struct stormfs {
  int ssl;
  int debug;
  int foreground;
  char *url;
  char *bucket;
  char *virtual_url;
  char *access_key;
  char *secret_key;
  char *mountpoint;
  mode_t root_mode;
} stormfs;

#define STORMFS_OPT(t, p, v) { t, offsetof(struct stormfs, p), v }

static struct fuse_opt stormfs_opts[] = {
  STORMFS_OPT("url=%s",        url,    0),
  STORMFS_OPT("use_ssl",       ssl,    1),
  STORMFS_OPT("stormfs_debug", debug,  1),

  FUSE_OPT_KEY("-d",            KEY_FOREGROUND),
  FUSE_OPT_KEY("debug",         KEY_FOREGROUND),
  FUSE_OPT_KEY("-f",            KEY_FOREGROUND),
  FUSE_OPT_KEY("--foreground",  KEY_FOREGROUND),
  FUSE_OPT_KEY("-h",            KEY_HELP),
  FUSE_OPT_KEY("--help",        KEY_HELP),
  FUSE_OPT_KEY("-V",            KEY_VERSION),
  FUSE_OPT_KEY("--version",     KEY_VERSION),
  FUSE_OPT_END
};

#define DEBUG(format, args...) \
        do { if (stormfs.debug) fprintf(stderr, format, args); } while(0)

static struct fuse_operations stormfs_oper = {
    .getattr  = stormfs_getattr,
    .readdir  = stormfs_readdir,
    .open     = stormfs_open,
    .read     = stormfs_read,
};

static uid_t
get_uid(const char *s)
{
  return (uid_t) strtoul(s, (char **) NULL, 10);
}

static gid_t
get_gid(const char *s)
{
  return (gid_t) strtoul(s, (char **) NULL, 10);
}

static gid_t
get_mode(const char *s)
{
  return (mode_t) strtoul(s, (char **) NULL, 10);
}

static time_t
get_mtime(const char *s)
{
  return (time_t) strtoul(s, (char **) NULL, 10);
}

static off_t
get_size(const char *s)
{
  return (off_t) strtoul(s, (char **) NULL, 10);
}

blkcnt_t get_blocks(off_t size)
{
  return size / 512 + 1;
}

static int
validate_mountpoint(const char *path, struct stat *stbuf)
{
  DIR *d;

  if(stat(path, &(*stbuf)) == -1) {
    fprintf(stderr, "unable to stat MOUNTPOINT %s: %s\n",
        path, strerror(errno));
    return -1;
  }

  if((d = opendir(path)) == NULL) {
    fprintf(stderr, "unable to open MOUNTPOINT %s: %s\n",
        path, strerror(errno));
    return -1;
  }

  closedir(d);

  return 0;
}

static int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  GList *meta = NULL;
  GList *head = NULL;
  GList *next = NULL;

  DEBUG("getattr: %s\n", path);

  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_nlink = 1;

  if(strcmp(path, "/") == 0) {
    stbuf->st_mode = stormfs.root_mode | S_IFDIR;

    return 0;
  }

  if(stormfs_curl_head(path, &meta) != 0)
    return -1;

  head = g_list_first(meta);
  while(head != NULL) {
    next = head->next;
    struct http_header *header = (struct http_header *) head->data;

    if(strcmp(header->key, "x-amz-meta-uid") == 0)
      stbuf->st_uid = get_uid(header->value);
    else if(strcmp(header->key, "x-amz-meta-gid") == 0)
      stbuf->st_uid = get_gid(header->value);
    else if(strcmp(header->key, "x-amz-meta-mtime") == 0)
      stbuf->st_mtime = get_mtime(header->value);
    else if(strcmp(header->key, "Last-Modified") == 0 && stbuf->st_mtime == 0)
      stbuf->st_mtime = get_mtime(header->value);
    else if(strcmp(header->key, "x-amz-meta-mode") == 0)
      stbuf->st_mode |= get_mode(header->value);
    else if(strcmp(header->key, "Content-Length") == 0)
      stbuf->st_size = get_size(header->value);
    else if(strcmp(header->key, "Content-Type") == 0) {
      if(strstr(header->value, "x-directory"))
        stbuf->st_mode |= S_IFDIR;
      else
        stbuf->st_mode |= S_IFREG;
    }

    g_free(header->key);
    g_free(header->value);
    g_free(header);

    head = next;
  }

  if(S_ISREG(stbuf->st_mode))
    stbuf->st_blocks = get_blocks(stbuf->st_size);

  g_list_free(meta);

  return 0;
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
    off_t offset, struct fuse_file_info *fi)
{
  int result;
  char *data;

  DEBUG("readdir: %s\n", path);

  result = stormfs_curl_get(path, &data);
  if(result != 0)
    return -EIO;

  printf("READDIR DATA: %s\n", data);
  g_free(data);

  return -ENOTSUP;
}

static int
stormfs_open(const char *path, struct fuse_file_info *fi)
{
  DEBUG("open: %s\n", path);
  return -ENOTSUP;
}

static int
stormfs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi)
{
  DEBUG("read: %s\n", path);
  return -ENOTSUP;
}

static int
stormfs_opt_proc(void *data, const char *arg, int key,
                 struct fuse_args *outargs)
{
  switch(key) {
    case FUSE_OPT_KEY_OPT:
      return 1;

    case FUSE_OPT_KEY_NONOPT:
      if(!stormfs.bucket) {
        stormfs.bucket = (char *) arg;
        return 0;
      }

      struct stat stbuf;
      if(validate_mountpoint(arg, &stbuf) == -1)
        abort();

      stormfs.mountpoint = (char *) arg;
      stormfs.root_mode = stbuf.st_mode;

      return 1;

    case KEY_FOREGROUND:
      stormfs.foreground = 1;
      return 1;

    default:
      fprintf(stderr, "error parsing options\n");
      abort();
  }
}

static int
stormfs_fuse_main(struct fuse_args *args)
{
  return fuse_main(args->argc, args->argv, &stormfs_oper, NULL);
}

char *
stormfs_virtual_url(char *url, char *bucket)
{
  char *tmp;
  char v[strlen(url) + strlen(bucket) + 9];

  if(stormfs.ssl || (strcasestr(url, "https://")) != NULL) {
    strcpy(v, "https://");
    strncat(v, bucket, strlen(bucket));
    strncat(v, ".", 1);
    strncat(v, url + 8, strlen(url) - 8);
  } else {
    strcpy(v, "http://");
    strncat(v, bucket, strlen(bucket));
    strncat(v, ".", 1);
    strncat(v, url + 7, strlen(url) - 7);
  }

  tmp = strdup(v);

  return tmp;
}

static int
stormfs_get_credentials(char **access_key, char **secret_key)
{
  *access_key = getenv("AWS_ACCESS_KEY_ID");
  *secret_key = getenv("AWS_SECRET_ACCESS_KEY");

  if(*access_key == NULL || *secret_key == NULL)
    return -1;

  return 0;
}

static int
stormfs_destroy(struct fuse_args *args)
{
  stormfs_curl_destroy();
  fuse_opt_free_args(args);
  g_free(stormfs.virtual_url);

  return 0;
}

int
main(int argc, char *argv[])
{
  int status;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  memset(&stormfs, 0, sizeof(struct stormfs));
  if(fuse_opt_parse(&args, &stormfs, stormfs_opts, stormfs_opt_proc) == -1) {
    fprintf(stderr, "error parsing command-line options\n");
    abort();
  }

  if(!stormfs.url)
    stormfs.url = "http://s3.amazonaws.com";

  stormfs.virtual_url = stormfs_virtual_url(stormfs.url, stormfs.bucket);

  DEBUG("STORMFS version:     %s\n", PACKAGE_VERSION);
  DEBUG("STORMFS url:         %s\n", stormfs.url);
  DEBUG("STORMFS bucket:      %s\n", stormfs.bucket);
  DEBUG("STORMFS virtual url: %s\n", stormfs.virtual_url);

  if(stormfs_get_credentials(&stormfs.access_key, &stormfs.secret_key) != 0) {
    fprintf(stderr, "missing api credentials\n");
    abort();
  }

  if((status = stormfs_curl_init(stormfs.bucket, stormfs.virtual_url)) != 0) {
    fprintf(stderr, "unable to initialize libcurl\n");
    abort();
  }

  stormfs_curl_set_auth(stormfs.access_key, stormfs.secret_key);

  status = stormfs_fuse_main(&args);

  stormfs_destroy(&args);

  return status;
}
