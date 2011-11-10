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
#include <fuse.h>
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

static int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  DEBUG("getattr: %s\n", path);

  stormfs_curl_get(path);

  return -ENOTSUP;
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
                           off_t offset, struct fuse_file_info *fi)
{
  DEBUG("readdir: %s\n", path);
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
        stormfs.bucket = strdup(arg);
        return 0;
      }

      return 1;

    case KEY_FOREGROUND:
      stormfs.foreground = 1;
      return 1;

    default:
      fprintf(stderr, "error parsing options\n");
      exit(EXIT_FAILURE);
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
stormfs_get_credentials()
{
  char *access_key = NULL;
  char *secret_key = NULL;

  access_key = getenv("AWS_ACCESS_KEY");
  secret_key = getenv("AWS_SECRET_KEY");

  printf("ACCESS_KEY: %s\n", access_key);
  printf("SECRET_KEY: %s\n", secret_key);
}

static int
stormfs_destroy(struct fuse_args *args)
{
  stormfs_curl_destroy();
  fuse_opt_free_args(args);
  free(stormfs.virtual_url);

  return 0;
}

int
main(int argc, char *argv[])
{
  int status;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  memset(&stormfs, 0, sizeof(struct stormfs));
  if(fuse_opt_parse(&args, &stormfs, stormfs_opts, stormfs_opt_proc) == -1)
    return EXIT_FAILURE;

  if(!stormfs.url)
    stormfs.url = "http://s3.amazonaws.com";

  stormfs.virtual_url = stormfs_virtual_url(stormfs.url, stormfs.bucket);

  DEBUG("STORMFS version:     %s\n", PACKAGE_VERSION);
  DEBUG("STORMFS url:         %s\n", stormfs.url);
  DEBUG("STORMFS bucket:      %s\n", stormfs.bucket);
  DEBUG("STORMFS virtual url: %s\n", stormfs.virtual_url);

  stormfs_get_credentials();

  if((status = stormfs_curl_init(stormfs.virtual_url)) != 0) {
    fprintf(stderr, "unable to initialize libcurl\n");
    return EXIT_FAILURE;
  }

  status = stormfs_fuse_main(&args);

  stormfs_destroy(&args);

  return status;
}
