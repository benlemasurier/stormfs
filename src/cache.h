/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef stormfs_cache_H
#define stormfs_cache_H

#include <fuse.h>
#include <fuse_opt.h>

struct fuse_cache_operations {
  struct fuse_operations oper;
  int (*list_bucket) (const char *, GList **);
};

int cache_parse_options(struct fuse_args *args);
int cache_getattr(const char *path, struct stat *stbuf);

struct fuse_operations *cache_init(struct fuse_cache_operations *oper);

#endif /* stormfs_cache_H */
