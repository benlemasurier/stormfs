/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define FUSE_USE_VERSION 26

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include "stormfs.h"

static struct fuse_operations stormfs_oper;

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

int
main(int argc, char *argv[])
{
  // map FUSE bindings
  memset(&stormfs_oper, 0, sizeof(stormfs_oper));
  stormfs_oper.getattr = stormfs_getattr;
  stormfs_oper.readdir = stormfs_readdir;
  stormfs_oper.open    = stormfs_open;
  stormfs_oper.read    = stormfs_read;

  // hand off control to FUSE
  return fuse_main(argc, argv, &stormfs_oper, NULL);
}
