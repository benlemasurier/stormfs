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

struct
options {
  int debug;
  int foreground;
  char *url;
  char *bucket;
} options;

#define STORMFS_OPT(t, p, v) { t, offsetof(struct options, p), v }

static struct 
fuse_opt stormfs_opts[] = 
{
  STORMFS_OPT("url=%s",        url,    0),
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
        do { if (options.debug) fprintf(stderr, format, args); } while(0)

static struct 
fuse_operations stormfs_oper = {
    .getattr  = stormfs_getattr,
    .readdir  = stormfs_readdir,
    .open     = stormfs_open,
    .read     = stormfs_read,
};

static int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  return -ENOTSUP;
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
                           off_t offset, struct fuse_file_info *fi)
{
  return -ENOTSUP;
}

static int
stormfs_open(const char *path, struct fuse_file_info *fi)
{
  return -ENOTSUP;
}

static int
stormfs_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi)
{
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
      if(!options.bucket) {
        options.bucket = strdup(arg);
        return 0;
      }

      return 1;

    case KEY_FOREGROUND:
      options.foreground = 1;
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

int
main(int argc, char *argv[])
{
  int status;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  memset(&options, 0, sizeof(struct options));
  if(fuse_opt_parse(&args, &options, stormfs_opts, stormfs_opt_proc) == -1)
    return EXIT_FAILURE;

  DEBUG("STORMFS version: %s\n", PACKAGE_VERSION);

  if((status = stormfs_curl_init()) != 0) {
    fprintf(stderr, "unable to initialize libcurl\n");
    return EXIT_FAILURE;
  }

  status = stormfs_fuse_main(&args);

  stormfs_curl_destroy();
  fuse_opt_free_args(&args);

  return status;
}
