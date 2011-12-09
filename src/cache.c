/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * The contents of this file owe great credit to Miklos Szeredi and sshfs.
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define FUSE_USE_VERSION 26
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <pthread.h>
#include "stormfs.h"
#include "cache.h"

#define DEFAULT_CACHE_PATH "/tmp/stormfs"
#define DEFAULT_CACHE_TIMEOUT 300
#define MAX_CACHE_SIZE 10000
#define MIN_CACHE_CLEAN_INTERVAL 5
#define CACHE_CLEAN_INTERVAL 60

struct cache {
  int on;
  time_t last_cleaned;
  unsigned dir_timeout;
  unsigned stat_timeout;
  unsigned link_timeout;
  unsigned file_timeout;
  GHashTable *table;
  pthread_mutex_t lock;
  struct fuse_cache_operations *next_oper;
  char *path;
} cache;

struct node {
  time_t valid;
  time_t dir_valid;
  time_t link_valid;
  time_t stat_valid;
  time_t file_valid;
  struct stat stat;
  GList *dir;
  char *link;
  char *path;
};

static char *
cache_path(const char *path)
{
  size_t path_len  = strlen(path);
  size_t cache_len = strlen(cache.path);
  char *cache_path = g_malloc0(sizeof(char) * path_len + cache_len + 1);

  cache_path = strcpy(cache_path, cache.path);
  cache_path = strncat(cache_path, path, path_len);

  return cache_path;
}

static int
mkpath(const char *path)
{
  int result = 0;
  struct stat st;
  char *p = NULL, *dir = strdup(path);
  char *tmp = g_malloc0(sizeof(char) * strlen(cache.path) + strlen(dir) + 1);

  dir = dirname(dir);
  tmp = strcpy(tmp, cache.path);
  p = strtok(dir, "/"); 
  while(p != NULL) {
    tmp = strncat(tmp, "/", 1);
    tmp = strncat(tmp, p, strlen(p));

    if(stat(tmp, &st) == 0) {
      if(S_ISDIR(st.st_mode)) {
        p = strtok(NULL, "/");
        continue;
      }

      result = -ENOTDIR;
      break;
    }

    if(mkdir(tmp, S_IRWXU) == -1) {
      result = -errno;
      break;
    }

    p = strtok(NULL, "/");
  }

  free(tmp);
  free(dir);

  return result;
}

static struct node *
cache_lookup(const char *path)
{
  return (struct node *) g_hash_table_lookup(cache.table, path);
}

static struct node *
cache_get(const char *path)
{
  struct node *node = cache_lookup(path);
  if(node == NULL) {
    char *tmp = strdup(path);
    node = g_new0(struct node, 1);
    g_hash_table_insert(cache.table, tmp, node);
  }

  return node;
}

static void
free_node(gpointer node_)
{
  struct node *node = (struct node *) node_;
  g_list_free_full(node->dir, g_free);
  if(node->path != NULL) g_free(node->path);
  g_free(node);
}

static int
cache_clean_entry(void *key_, struct node *node, time_t *now)
{
  (void) key_;
  if(*now > node->valid)
    return TRUE;
  else
    return FALSE;
}

static void
cache_clean(void)
{
  time_t now = time(NULL);
  if(now > cache.last_cleaned + MIN_CACHE_CLEAN_INTERVAL &&
      (g_hash_table_size(cache.table) > MAX_CACHE_SIZE ||
       now > cache.last_cleaned + CACHE_CLEAN_INTERVAL)) {
    g_hash_table_foreach_remove(cache.table,
        (GHRFunc) cache_clean_entry, &now);
    cache.last_cleaned = now;
  }
}

static void
cache_purge(const char *path)
{
  g_hash_table_remove(cache.table, path);
}

static void
cache_purge_parent(const char *path)
{
  const char *s = strrchr(path, '/');
  if(s) {
    if(s == path)
      g_hash_table_remove(cache.table, "/");
    else {
      char *parent = g_strndup(path, s - path);
      cache_purge(parent);
      g_free(parent);
    }
  }
}

static void
cache_invalidate(const char *path)
{
  if(!cache.on) 
    return;

  pthread_mutex_lock(&cache.lock);
  cache_purge(path);
  pthread_mutex_unlock(&cache.lock);
}

static void
cache_invalidate_dir(const char *path)
{
  pthread_mutex_lock(&cache.lock);
  cache_purge(path);
  cache_purge_parent(path);
  pthread_mutex_unlock(&cache.lock);
}

static int
cache_del_children(const char *key, void *val_, const char *path)
{
  (void) val_;
  if(strncmp(key, path, strlen(path)) == 0)
    return TRUE;
  else
    return FALSE;
}

static void
cache_do_rename(const char *from, const char *to)
{
  pthread_mutex_lock(&cache.lock);
  g_hash_table_foreach_remove(cache.table, (GHRFunc) cache_del_children,
      (char *) from);
  cache_purge(from);
  cache_purge(to);
  cache_purge_parent(from);
  cache_purge_parent(to);
  pthread_mutex_unlock(&cache.lock);
}

void
cache_add_attr(const char *path, const struct stat *stbuf)
{
  time_t now;
  struct node *node;

  if(!cache.on)
    return;

  pthread_mutex_lock(&cache.lock);
  node = cache_get(path);
  now  = time(NULL);
  node->stat = *stbuf;
  node->stat_valid = time(NULL) + cache.stat_timeout;
  if(node->stat_valid > node->valid)
    node->valid = node->stat_valid;
  cache_clean();
  pthread_mutex_unlock(&cache.lock);
}

static int
cache_get_attr(const char *path, struct stat *stbuf)
{
  int result = -EAGAIN;
  struct node *node;

  pthread_mutex_lock(&cache.lock);
  node = cache_lookup(path);
  if(node != NULL) {
    time_t now = time(NULL);
    if(node->stat_valid - now >= 0) {
      *stbuf = node->stat;
      result = 0;
    }
  }
  pthread_mutex_unlock(&cache.lock);

  return result;
}

static void
cache_add_dir(const char *path, GList *files)
{
  time_t now;
  struct node *node;

  pthread_mutex_lock(&cache.lock);
  node = cache_get(path);
  now = time(NULL);
  node->dir = files;
  node->dir_valid = time(NULL) + cache.dir_timeout;
  if(node->dir_valid > node->valid)
    node->valid = node->dir_valid;
  cache_clean();
  pthread_mutex_unlock(&cache.lock);
}

static void
cache_add_link(const char *path, const char *link, size_t size)
{
  struct node *node;
  time_t now;

  pthread_mutex_lock(&cache.lock);
  node = cache_get(path);
  now = time(NULL);
  g_free(node->link);
  node->link = g_strndup(link, strnlen(link, size - 1));
  node->link_valid = time(NULL) + cache.link_timeout;
  if(node->link_valid > node->valid)
    node->valid = node->link_valid;
  cache_clean();
  pthread_mutex_unlock(&cache.lock);
}

static void
cache_add_file(const char *path, uint64_t fd, mode_t mode)
{
  int cache_fd;
  struct node *node;
  time_t now;
  char buf[BUFSIZ];
  ssize_t n;
  struct stat st;

  pthread_mutex_lock(&cache.lock);
  node = cache_get(path);
  now = time(NULL);
  node->path = cache_path(path);

  if(stat(node->path, &st) == 0)
    if(unlink(node->path) != 0)
      perror("unlink");

  if(mkpath(path) != 0)
    fprintf(stderr, "error creating cache path: %s\n", path);
  
  if((cache_fd = open(node->path, O_CREAT | O_EXCL | O_RDWR, mode)) == -1)
    fprintf(stderr, "error creating cache file: %s\n", path);

  while((n = read(fd, buf, BUFSIZ)) > 0)
    if(write(cache_fd, buf, n) == -1)
      fprintf(stderr, "error writing to cache file: %s\n", path);

  close(cache_fd);

  node->file_valid = time(NULL) + cache.file_timeout;
  if(node->file_valid > node->valid)
    node->valid = node->file_valid;
  cache_clean();
  pthread_mutex_unlock(&cache.lock);
}

static int
cache_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  int result;
  if((result = cache.next_oper->oper.create(path, mode, fi)) != 0)
    return result;

  cache_invalidate_dir(path);
  return result;
}

static int
cache_chmod(const char *path, mode_t mode)
{
  int result;
  if((result = cache.next_oper->oper.chmod(path, mode)) != 0)
    return result;

  cache_invalidate(path);
  return result;
}

static int
cache_chown(const char *path, uid_t uid, gid_t gid)
{
  int result;
  if((result = cache.next_oper->oper.chown(path, uid, gid)) != 0)
    return result;

  cache_invalidate(path);
  return result;
}

static int
cache_getattr(const char *path, struct stat *stbuf)
{
  int result;
  if((result = cache_get_attr(path, stbuf)) != 0) {
    result = cache.next_oper->oper.getattr(path, stbuf);
    if(result == 0)
      cache_add_attr(path, stbuf);
  }

  return result;
}

static int
cache_flush(const char *path, struct fuse_file_info *fi)
{
  return cache.next_oper->oper.flush(path, fi);
}

static int
cache_mkdir(const char *path, mode_t mode)
{
  int result;
  if((result = cache.next_oper->oper.mkdir(path, mode)) != 0)
    return result;

  cache_invalidate_dir(path);
  return result;
}

static int
cache_mknod(const char *path, mode_t mode, dev_t rdev)
{
  int result;
  if((result = cache.next_oper->oper.mknod(path, mode, rdev)) != 0)
    return result;

  cache_invalidate_dir(path);

  return result;
}

static int
cache_open(const char *path, struct fuse_file_info *fi)
{
  FILE *f;
  int result;
  struct node *node;

  node = cache_lookup(path);

  if(node != NULL && node->path != NULL) {
    time_t now = time(NULL);
    if(node->file_valid - now >= 0) {
      if((unsigned int) fi->flags & O_TRUNC)
        if(truncate(node->path, 0) == -1)
          return -errno;

      // FIXME: mode should reflect fi->flags
      f = fopen(node->path, "a+");
      fi->fh = fileno(f);
      fsync(fi->fh);

      return 0;
    }
  }

  if((result = cache.next_oper->oper.open(path, fi)) != 0)
    return result;

  cache_add_file(path, fi->fh, node->stat.st_mode);

  return result;
}

static int
cache_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  int result = cache.next_oper->oper.read(path, buf, size, offset, fi);

  return result;
}

static int
cache_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
    off_t offset, struct fuse_file_info *fi)
{
  int result;
  struct node *node;
  GList *files   = NULL, 
        *head    = NULL,
        *next    = NULL;

  filler(buf, ".",  0, 0);
  filler(buf, "..", 0, 0);

  pthread_mutex_lock(&cache.lock);
  node = cache_lookup(path);
  if(node != NULL && node->dir != NULL) {
    head = g_list_first(node->dir);
    while(head != NULL) {
      next = head->next;
      struct file *file = head->data;
      filler(buf, (const char *) file->name, 0, 0);
      head = next;
    }
    pthread_mutex_unlock(&cache.lock);
    return 0;
  }
  pthread_mutex_unlock(&cache.lock);

  result = cache.next_oper->list_bucket(path, &files);
  if(result != 0) {
    g_list_free_full(head, (GDestroyNotify) free_file);
    return result;
  }

  result = stormfs_getattr_multi(path, files);

  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;
    struct file *file = head->data;
    char *fullpath = get_path(path, file->name);
    filler(buf, (const char *) file->name, 0, 0);
    cache_add_attr(fullpath, file->stbuf);
    g_free(fullpath);
    head = next;
  }

  head = g_list_first(files);
  cache_add_dir(path, head);

  return result;
}

static int
cache_readlink(const char *path, char *buf, size_t size)
{
  struct node *node;
  int result;

  pthread_mutex_lock(&cache.lock);
  node = cache_lookup(path);
  if(node != NULL) {
    time_t now = time(NULL);
    if(node->link_valid - now >= 0) {
      strncpy(buf, node->link, size - 1);
      buf[size-1] = '\0';
      pthread_mutex_unlock(&cache.lock);
      return 0;
    }
  }
  pthread_mutex_unlock(&cache.lock);

  if((result = cache.next_oper->oper.readlink(path, buf, size)) != 0)
    return result;

  cache_add_link(path, buf, size);
  return result;
}

static int
cache_release(const char *path, struct fuse_file_info *fi)
{
  int result = cache.next_oper->oper.release(path, fi);
  if(result == 0)
    if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY))
      cache_invalidate_dir(path);

  return result;
}

static int
cache_rename(const char *from, const char *to)
{
  int result;
  if((result = cache.next_oper->oper.rename(from, to)) != 0)
    return result;

  cache_do_rename(from, to);
  return result;
}

static int
cache_rmdir(const char *path)
{
  int result;
  if((result = cache.next_oper->oper.rmdir(path)) != 0)
    return result;

  cache_invalidate_dir(path);
  return result;
}

static int
cache_symlink(const char *from, const char *to)
{
  int result;
  if((result = cache.next_oper->oper.symlink(from, to)) != 0)
    return result;

  cache_invalidate_dir(to);
  return result;
}

static int
cache_truncate(const char *path, off_t size)
{
  int result;
  if((result = cache.next_oper->oper.truncate(path, size)) != 0)
    return result;

  cache_invalidate(path);
  return result;
}

static int
cache_unlink(const char *path)
{
  int result = cache.next_oper->oper.unlink(path);
  if(result == 0)
    cache_invalidate_dir(path);

  return result;
}

static int
cache_utimens(const char *path, const struct timespec ts[2])
{
  int result = cache.next_oper->oper.utimens(path, ts);
  if(result == 0)
    cache_invalidate(path);

  return result;
}

static int
cache_write(const char *path, const char *buf, 
    size_t size, off_t offset, struct fuse_file_info *fi)
{
  int result = cache.next_oper->oper.write(path, buf, size, offset, fi);
  if(result == 0)
    cache_invalidate(path);

  return result;
}

static int
create_cache_path(const char *path)
{
  fprintf(stderr, "warning: %s does not exist, creating.\n", path);
  return mkdir(path, S_IRWXU);
}

static int
validate_cache_path(const char *path)
{
  int result;
  struct stat st;

  result = stat(path, &st);
  if(errno == ENOENT) {
    if((result = create_cache_path(path)) != 0)
      return result;
    else
      result = stat(path, &st);
  }

  if(result != 0) {
    perror("stat");
    return result;
  }

  if(!S_ISDIR(st.st_mode)) {
    fprintf(stderr, "error: %s is not a directory\n", path);
    return -ENOTDIR;
  }

  return result;
}

static void
cache_unity_fill(struct fuse_cache_operations *oper, 
    struct fuse_operations *cache_oper)
{
  cache_oper->create   = oper->oper.create;
  cache_oper->chmod    = oper->oper.chmod;
  cache_oper->chown    = oper->oper.chown;
  cache_oper->destroy  = oper->oper.destroy;
  cache_oper->getattr  = oper->oper.getattr;
  cache_oper->init     = oper->oper.init;
  cache_oper->flush    = oper->oper.flush;
  cache_oper->mkdir    = oper->oper.mkdir;
  cache_oper->mknod    = oper->oper.mknod;
  cache_oper->open     = oper->oper.open;
  cache_oper->read     = oper->oper.read;
  cache_oper->readdir  = oper->oper.readdir;
  cache_oper->readlink = oper->oper.readlink;
  cache_oper->release  = oper->oper.release;
  cache_oper->rename   = oper->oper.rename;
  cache_oper->rmdir    = oper->oper.rmdir;
  cache_oper->statfs   = oper->oper.statfs;
  cache_oper->symlink  = oper->oper.symlink;
  cache_oper->truncate = oper->oper.truncate;
  cache_oper->unlink   = oper->oper.unlink;
  cache_oper->utimens  = oper->oper.utimens;
  cache_oper->write    = oper->oper.write;
}

static void
cache_fill(struct fuse_cache_operations *oper,
    struct fuse_operations *cache_oper)
{
  cache_oper->create   = oper->oper.create   ? cache_create   : NULL;
  cache_oper->chmod    = oper->oper.chmod    ? cache_chmod    : NULL;
  cache_oper->chown    = oper->oper.chown    ? cache_chown    : NULL;
  cache_oper->getattr  = oper->oper.getattr  ? cache_getattr  : NULL;
  cache_oper->flush    = oper->oper.flush    ? cache_flush    : NULL;
  cache_oper->mkdir    = oper->oper.mkdir    ? cache_mkdir    : NULL;
  cache_oper->mknod    = oper->oper.mknod    ? cache_mknod    : NULL;
  cache_oper->open     = oper->oper.open     ? cache_open     : NULL;
  cache_oper->read     = oper->oper.read     ? cache_read     : NULL;
  cache_oper->readdir  = oper->list_bucket   ? cache_readdir  : NULL;
  cache_oper->readlink = oper->oper.readlink ? cache_readlink : NULL;
  cache_oper->release  = oper->oper.release  ? cache_release  : NULL;
  cache_oper->rename   = oper->oper.rename   ? cache_rename   : NULL;
  cache_oper->rmdir    = oper->oper.rmdir    ? cache_rmdir    : NULL;
  cache_oper->symlink  = oper->oper.symlink  ? cache_symlink  : NULL;
  cache_oper->truncate = oper->oper.truncate ? cache_truncate : NULL;
  cache_oper->unlink   = oper->oper.unlink   ? cache_unlink   : NULL;
  cache_oper->utimens  = oper->oper.utimens  ? cache_utimens  : NULL;
  cache_oper->write    = oper->oper.write    ? cache_write    : NULL;
}

struct fuse_operations *
cache_init(struct fuse_cache_operations *oper)
{
  static struct fuse_operations cache_oper;
  cache.next_oper = oper;

  cache_unity_fill(oper, &cache_oper);
  if(cache.on) {
    cache_fill(oper, &cache_oper);
    pthread_mutex_init(&cache.lock, NULL);
    cache.table = g_hash_table_new_full(g_str_hash, g_str_equal,
        g_free, free_node);
    if(cache.table == NULL) {
      fprintf(stderr, "error initializing cache\n");
      return NULL;
    }
  }

  return &cache_oper;
}

static const struct fuse_opt cache_opts[] = {
  {"cache=yes",             offsetof(struct cache, on),           1},
  {"cache=no",              offsetof(struct cache, on),           0},
  {"cache_path=%s",         offsetof(struct cache, path),         0},
  {"cache_timeout=%u",      offsetof(struct cache, stat_timeout), 0},
  {"cache_timeout=%u",      offsetof(struct cache, dir_timeout),  0},
  {"cache_stat_timeout=%u", offsetof(struct cache, stat_timeout), 0},
  {"cache_link_timeout=%u", offsetof(struct cache, link_timeout), 0},
  {"cache_dir_timeout=%u",  offsetof(struct cache, dir_timeout),  0},
  {"cache_file_timeout=%u", offsetof(struct cache, file_timeout), 0},
  FUSE_OPT_END
};

int
cache_parse_options(struct fuse_args *args)
{
  int result;

  cache.on = 1;
  cache.path = DEFAULT_CACHE_PATH;
  cache.dir_timeout  = DEFAULT_CACHE_TIMEOUT;
  cache.stat_timeout = DEFAULT_CACHE_TIMEOUT;
  cache.link_timeout = DEFAULT_CACHE_TIMEOUT;
  cache.file_timeout = DEFAULT_CACHE_TIMEOUT;

  if((result = fuse_opt_parse(args, &cache, cache_opts, NULL)) == -1)
    return result;

  return validate_cache_path(cache.path);
}
