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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib.h>
#include "stormfs.h"
#include "s3.h"

struct proxy {
  struct stormfs *stormfs;
} proxy;

void
proxy_destroy(void)
{
  switch(proxy.stormfs->service) {
    case AMAZON:
      s3_destroy();
      break;
  }
}

int
proxy_getattr(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_getattr(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_getattr_multi(const char *path, GList *files)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_getattr_multi(path, files);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_chmod(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_chmod(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_chown(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_chown(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_create(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_create(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_init(struct stormfs *stormfs)
{
  int result;

  proxy.stormfs = stormfs;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_init(proxy.stormfs);
      break;
    default:
      printf("SFDSLJSLDFJSDFJ\n");
      result = -EINVAL;
  }

  return result;
}

int
proxy_mkdir(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_mkdir(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_mknod(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_mknod(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_open(const char *path, FILE *f)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_open(path, f);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_readdir(const char *path, GList **files)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_readdir(path, files);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_release(const char *path, int fd, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_release(path, fd, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_rename(const char *from, const char *to, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_rename(from, to, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_rmdir(const char *path)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_rmdir(path);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_symlink(const char *from, const char *to, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_symlink(from, to, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_unlink(const char *path)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_unlink(path);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}

int
proxy_utimens(const char *path, struct stat *st)
{
  int result;

  switch(proxy.stormfs->service) {
    case AMAZON:
      result = s3_utimens(path, st);
      break;
    default:
      result = -EINVAL;
  }

  return result;
}
