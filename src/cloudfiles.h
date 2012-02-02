/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef cloudfiles_H
#define cloudfiles_H

void cloudfiles_destroy(void);
int cloudfiles_getattr(const char *path, struct stat *st);
int cloudfiles_getattr_multi(const char *path, GList *files);
int cloudfiles_chmod(const char *path, struct stat *st);
int cloudfiles_chown(const char *path, struct stat *st);
int cloudfiles_create(const char *path, struct stat *st);
int cloudfiles_init(struct stormfs *stormfs);
int cloudfiles_mkdir(const char *path, struct stat *st);
int cloudfiles_mknod(const char *path, struct stat *st);
int cloudfiles_open(const char *path, FILE *f);
int cloudfiles_readdir(const char *path, GList **files);
int cloudfiles_release(const char *path, int fd, struct stat *st);
int cloudfiles_rename(const char *from, const char *to, struct stat *st);
int cloudfiles_rmdir(const char *path);
int cloudfiles_symlink(const char *from, const char *to, struct stat *st);
int cloudfiles_unlink(const char *path);
int cloudfiles_utimens(const char *path, struct stat *st);

#endif // cloudfiles_H
