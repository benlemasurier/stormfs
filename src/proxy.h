/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef proxy_H
#define proxy_H

void proxy_destroy(void);
int proxy_getattr(const char *path, struct stat *st);
int proxy_getattr_multi(const char *path, GList *files);
int proxy_chmod(const char *path, struct stat *st);
int proxy_chown(const char *path, struct stat *st);
int proxy_create(const char *path, struct stat *st);
int proxy_init(struct stormfs *stormfs);
int proxy_mkdir(const char *path, struct stat *st);
int proxy_mknod(const char *path, struct stat *st);
int proxy_open(const char *path, FILE *f);
int proxy_readdir(const char *path, GList **files);
int proxy_release(const char *path, int fd, struct stat *st);
int proxy_rename(const char *from, const char *to, struct stat *st);
int proxy_rmdir(const char *path);
int proxy_symlink(const char *from, const char *to, struct stat *st);
int proxy_unlink(const char *path);
int proxy_utimens(const char *path, struct stat *st);

#endif // proxy_H
