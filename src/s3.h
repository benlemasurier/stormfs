/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef s3_H
#define s3_H

int s3_getattr(const char *path, struct stat *st);
int s3_chmod(const char *path, struct stat *st);
int s3_chown(const char *path, struct stat *st);
int s3_create(const char *path, struct stat *st);
int s3_unlink(const char *path);

#endif // s3_H
