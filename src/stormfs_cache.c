/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * The contents of this file owe great credit to Miklos Szeredi and sshfs.
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <sys/select.h>
#include <fuse.h>
#include <fuse_opt.h>
#include <pthread.h>
#include "stormfs_cache.h"
#include "stormfs.h"

#define DEFAULT_CACHE_TIMEOUT 300
#define MAX_CACHE_SIZE 10000
#define MIN_CACHE_CLEAN_INTERVAL 5
#define CACHE_CLEAN_INTERVAL 60

struct cache {
  int on;
  time_t last_cleaned;
  unsigned dir_timeout;
  unsigned stat_timeout;
  GHashTable *table;
  pthread_mutex_t lock;
  struct fuse_cache_operations *next_oper;
} cache;

struct node {
  time_t valid;
  time_t dir_valid;
  time_t stat_valid;
  struct stat stat;
  GList *dir;
};

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

static char *
get_path(const char *path, const char *name)
{
  char *fullpath = g_malloc(sizeof(char) * strlen(path) + strlen(name) + 2);
  strcpy(fullpath, path);
  if(strcmp(path, "/") != 0)
    strncat(fullpath, "/", 1);
  strncat(fullpath, name, strlen(name));

  return fullpath;
}

static void
free_node(gpointer node_)
{
  struct node *node = (struct node *) node_;
  g_list_free_full(node->dir, g_free);
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

void
cache_invalidate(const char *path)
{
  if(!cache.on) 
    return;

  pthread_mutex_lock(&cache.lock);
  cache_purge(path);
  pthread_mutex_unlock(&cache.lock);
}

void
cache_invalidate_dir(const char *path)
{
  pthread_mutex_lock(&cache.lock);
  cache_purge(path);
  cache_purge_parent(path);
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
cache_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
    off_t offset, struct fuse_file_info *fi)
{
  int result;
  struct node *node;
  GList *files   = NULL, 
        *head    = NULL,
        *next    = NULL;

  pthread_mutex_lock(&cache.lock);
  node = cache_lookup(path);
  if(node != NULL && node->dir != NULL) {
    head = g_list_first(node->dir);
    while(head != NULL) {
      next = head->next;
      filler(buf, (const char *) head->data, 0, 0);
      head = next;
    }
    pthread_mutex_unlock(&cache.lock);
    return 0;
  }
  pthread_mutex_unlock(&cache.lock);

  result = cache.next_oper->list_bucket(path, &files);
  if(result != 0) {
    g_list_free_full(head, g_free);
    return result;
  }

  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;
    filler(buf, (const char *) head->data, 0, 0);
    head = next;
  }

  head = g_list_first(files);
  cache_add_dir(path, head);

  return result;
}

static int
cache_release(const char *path, struct fuse_file_info *fi)
{
  int result = cache.next_oper->oper.release(path, fi);
  if(result == 0)
    cache_invalidate_dir(path);

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
  cache_oper->create  = oper->oper.create  ? cache_create  : NULL;
  cache_oper->getattr = oper->oper.getattr ? cache_getattr : NULL;
  cache_oper->flush   = oper->oper.flush   ? cache_flush   : NULL;
  cache_oper->readdir = oper->list_bucket  ? cache_readdir : NULL;
  cache_oper->release = oper->oper.release ? cache_release : NULL;
  cache_oper->unlink  = oper->oper.unlink  ? cache_unlink  : NULL;
  cache_oper->utimens = oper->oper.utimens ? cache_utimens : NULL;
  cache_oper->write   = oper->oper.write   ? cache_write   : NULL;
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
  {"cache=yes",             offsetof(struct cache, on), 1},
  {"cache=no",              offsetof(struct cache, on), 0},
  {"cache_timeout=%u",      offsetof(struct cache, stat_timeout), 0},
  {"cache_timeout=%u",      offsetof(struct cache, dir_timeout),  0},
  {"cache_stat_timeout=%u", offsetof(struct cache, stat_timeout), 0},
  {"cache_dir_timeout=%u", offsetof(struct cache,  dir_timeout),  0},
  FUSE_OPT_END
};

int
cache_parse_options(struct fuse_args *args)
{
  cache.on = 1;
  cache.dir_timeout  = DEFAULT_CACHE_TIMEOUT;
  cache.stat_timeout = DEFAULT_CACHE_TIMEOUT;

  return fuse_opt_parse(args, &cache, cache_opts, NULL);
}
