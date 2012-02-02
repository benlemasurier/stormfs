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

struct cloudfiles {
  struct stormfs *stormfs;
} cloudfiles;

void
cloudfiles_destroy(void)
{
}

int
cloudfiles_getattr(const char *path, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_getattr_multi(const char *path, GList *files)
{
  return -ENOTSUP;
}

int
cloudfiles_chmod(const char *path, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_chown(const char *path, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_create(const char *path, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_init(struct stormfs *stormfs)
{
  return -ENOTSUP;
}

int
cloudfiles_mkdir(const char *path, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_mknod(const char *path, struct stat *st)
{
  return -ENOTSUP;
}

int
cloudfiles_open(const char *path, FILE *f)
{
  return -ENOTSUP;
}

int
cloudfiles_readdir(const char *path, GList **files)
{
  return -ENOTSUP;
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
  return -ENOTSUP;
}

int
cloudfiles_unlink(const char *path)
{
  return -ENOTSUP;
}

int
cloudfiles_utimens(const char *path, struct stat *st)
{
  return -ENOTSUP;
}
