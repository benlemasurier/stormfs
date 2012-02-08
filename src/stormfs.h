/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#ifndef stormfs_H
#define stormfs_H

#define FIVE_GB 5368709120LL

enum service {
  S3,
  CLOUDFILES
};

struct stormfs {
  enum service service;
  bool ssl;
  bool rrs;
  int encryption;
  int cache;
  int foreground;
  int verify_ssl;
  char *acl;
  char *api;
  char *url;
  char *bucket;
  char *config;
  char *debug;
  char *progname;
  char *username;
  char *virtual_url;
  char *access_key;
  char *secret_key;
  char *mime_path;
  char *mountpoint;
  char *storage_class;
  char *expires;
  char *cache_path;
  unsigned cache_timeout;
  mode_t root_mode;
  GHashTable *mime_types;
};

struct file {
  char *name;           /* file name */
  char *path;           /* file path */
  GList *dir;           /* list of files in this directory */
  GList *headers;       /* http headers */
  struct stat *st;      /* stat(2) buffer */
  time_t valid;         /* entry timeout */
  pthread_mutex_t lock; /* file-level lock */
};

blkcnt_t get_blocks(off_t size);
char *get_path(const char *path, const char *name);
const char *get_mime_type(const char *filename);
char *stormfs_virtual_url(char *url, char *bucket);
void free_file(struct file *f);
int stormfs_getattr(const char *path, struct stat *stbuf);
int stormfs_unlink(const char *path);

#endif // stormfs_H
