/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include "stormfs.h"

#ifndef s3_H
#define s3_H

int s3_getattr(const char *path, struct stat *st);
int s3_getattr_multi(const char *path, GList *files);
int s3_chmod(const char *path, struct stat *st);
int s3_chown(const char *path, struct stat *st);
int s3_create(const char *path, struct stat *st);
int s3_init(struct stormfs *stormfs);
int s3_mkdir(const char *path, struct stat *st);
int s3_mknod(const char *path, struct stat *st);
int s3_open(const char *path, FILE *f);
int s3_release(const char *path, int fd, struct stat *st);
int s3_readdir(const char *path, GList **files);
int s3_rename(const char *from, const char *to, struct stat *st);
int s3_rmdir(const char *path);
int s3_symlink(const char *from, const char *to, struct stat *st);
int s3_unlink(const char *path);
int s3_utimens(const char *path, struct stat *st);

#endif // s3_H
