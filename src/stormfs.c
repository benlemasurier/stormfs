/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define FUSE_USE_VERSION 26
#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <pthread.h>
#include <glib.h>
#include "stormfs.h"
#include "proxy.h"
#include "curl.h"

#define CONFIG SYSCONFDIR "/stormfs.conf"
#define DEFAULT_CACHE_TIMEOUT 300
#define CACHE_CLEAN_INTERVAL  60

#define STORMFS_OPT(t, p, v) { t, offsetof(struct stormfs, p), v }
#define DEBUG(format, ...) \
        do { if (stormfs.debug) fprintf(stderr, format, __VA_ARGS__); } while(0)

struct stormfs stormfs;

struct cache {
  bool on;
  char *path;
  int timeout;
  time_t last_cleaned;
  GHashTable *files;
  pthread_mutex_t lock;
} cache;

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_FOREGROUND,
};

static struct fuse_opt stormfs_opts[] = {
  STORMFS_OPT("service=%s",       api,           0),
  STORMFS_OPT("acl=%s",           acl,           0),
  STORMFS_OPT("config=%s",        config,        0),
  STORMFS_OPT("url=%s",           url,           0),
  STORMFS_OPT("username=%s",      username,      0),
  STORMFS_OPT("encryption",       encryption,    1),
  STORMFS_OPT("expires=%s",       expires,       0),
  STORMFS_OPT("use_ssl",          ssl,           true),
  STORMFS_OPT("no_verify_ssl",    verify_ssl,    0),
  STORMFS_OPT("use_rrs",          rrs,           true),
  STORMFS_OPT("nocache",          cache,         0),
  STORMFS_OPT("stormfs_debug",    debug,         true),
  STORMFS_OPT("mime_path=%s",     mime_path,     0),
  STORMFS_OPT("cache_path=%s",    cache_path,    0),
  STORMFS_OPT("cache_timeout=%u", cache_timeout, 0),

  FUSE_OPT_KEY("-d",            KEY_FOREGROUND),
  FUSE_OPT_KEY("--debug",       KEY_FOREGROUND),
  FUSE_OPT_KEY("-f",            KEY_FOREGROUND),
  FUSE_OPT_KEY("--foreground",  KEY_FOREGROUND),
  FUSE_OPT_KEY("-h",            KEY_HELP),
  FUSE_OPT_KEY("--help",        KEY_HELP),
  FUSE_OPT_KEY("-V",            KEY_VERSION),
  FUSE_OPT_KEY("--version",     KEY_VERSION),
  FUSE_OPT_END
};

blkcnt_t
get_blocks(off_t size)
{
  return size / 512 + 1;
}

static int
valid_path(const char *path)
{
  char *p = NULL;
  char *tmp = strdup(path);

  if(strlen(path) > PATH_MAX)
    return -ENAMETOOLONG;

  p = strtok(tmp, "/");
  while(p != NULL) {
    if(strlen(p) > NAME_MAX)
      return -ENAMETOOLONG;

    p = strtok(NULL, "/");
  }

  free(tmp);

  return 0;
}

static int
validate_cache_path(const char *path)
{
  int result;
  struct stat st;

  errno = 0;
  result = stat(path, &st);

  // If the directory does not exist, create it.
  if(errno == ENOENT) {
    DEBUG("%s does not exist, creating.\n", path);
    if((result = mkdir(path, S_IRWXU)) != 0) {
      perror("mkdir");
      return result;
    } else {
      result = stat(path, &st);
    }
  }

  if(result != 0) {
    perror("stat");
    return result;
  }

  if(!S_ISDIR(st.st_mode)) {
    DEBUG("error: %s is not a directory\n", path);
    return -ENOTDIR;
  }

  return result;
}

static int
cache_mkpath(const char *path)
{
  int result = 0;
  struct stat st;
  char *path_copy = strdup(path);
  char *p = NULL, *dir = dirname(path_copy);
  char *tmp;

  tmp = g_malloc0(sizeof(char) *
      strlen(stormfs.cache_path) + strlen(dir) + 1);

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
  free(path_copy);

  return result;
}

static char *
cache_path(struct file *f)
{
  char *fullpath;

  fullpath = g_malloc0(sizeof(char) * strlen(cache.path)
      + strlen(f->path) + 1);
  fullpath = strcpy(fullpath, cache.path);
  fullpath = strncat(fullpath, f->path, strlen(f->path));

  return fullpath;
}

static int
cache_create_file(struct file *f)
{
  int result;
  char *cp;

  cp = cache_path(f);
  if((result = cache_mkpath(cp)) != 0)
    return result;

  unlink(cp);

  result = open(cp, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  if(result == -1)
    perror("open");

  free(cp);

  return result;
}

static int
cache_mknod(struct file *f, mode_t mode, dev_t rdev)
{
  int result;
  char *cp;

  cp = cache_path(f);
  if((result = cache_mkpath(cp)) != 0)
    return result;

  unlink(cp);

  result = mknod(cp, mode, rdev);
  if(result == -1)
    perror("mknod");

  free(cp);

  return result;
}

void
free_file(struct file *f)
{
  free(f->name);
  free(f->path);
  if(f->st != NULL) free(f->st);
  if(f->dir != NULL) g_list_free(f->dir);
  free_headers(f->headers);
  pthread_mutex_destroy(&f->lock);
  free(f);
}

void
free_files(GList *files)
{
  g_list_foreach(files, (GFunc) free_file, NULL);
  g_list_free(files);
}

static int
cache_init(void)
{
  cache.on = (stormfs.cache) ? true : false;
  cache.timeout = stormfs.cache_timeout;
  cache.last_cleaned = time(NULL);
  pthread_mutex_init(&cache.lock, NULL);
  cache.files = g_hash_table_new_full(g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) free_file);

  validate_cache_path(stormfs.cache_path);
  if(asprintf(&cache.path, "%s/%s",
      stormfs.cache_path, stormfs.bucket) == -1) {
    fprintf(stderr, "unable to allocate memory\n");
    exit(EXIT_FAILURE);
  }

  return 0;
}

static int
cache_destroy(void)
{
  free(cache.path);
  g_hash_table_destroy(cache.files);
  pthread_mutex_destroy(&cache.lock);

  return 0;
}

static void
cache_invalidate(const char *path)
{
  pthread_mutex_lock(&cache.lock);
  g_hash_table_remove(cache.files, path);
  pthread_mutex_unlock(&cache.lock);
}

static void
cache_invalidate_dir(const char *path)
{
  cache_invalidate(path);

  const char *s = strrchr(path, '/');
  if(s) {
    if(s == path)
      g_hash_table_remove(cache.files, "/");
    else {
      char *parent = g_strndup(path, s - path);
      cache_invalidate(parent);
      free(parent);
    }
  }
}

static void
cache_touch(struct file *f)
{
  f->valid = time(NULL) + cache.timeout;
}

static int
cache_clean_file(void *key_, struct file *f, time_t *now)
{
  (void) key_;
  if(*now > f->valid)
    return TRUE;

  return FALSE;
}

static void
cache_clean()
{
  time_t now = time(NULL);

  if(now > (cache.last_cleaned + CACHE_CLEAN_INTERVAL)) {
    g_hash_table_foreach_remove(cache.files, 
        (GHRFunc) cache_clean_file, &now);

    cache.last_cleaned = now;
  }
}

static struct file *
cache_insert(const char *path)
{
  struct file *f = g_new0(struct file, 1);

  f->path = strdup(path);
  f->name = strdup(basename(f->path));
  f->headers = NULL;
  f->st = NULL;
  pthread_mutex_init(&f->lock, NULL);
  cache_touch(f);

  g_hash_table_insert(cache.files, strdup(path), f);

  return f;
}

static struct file *
cache_get(const char *path)
{
  struct file *f = NULL;

  pthread_mutex_lock(&cache.lock);
  cache_clean();
  f = g_hash_table_lookup(cache.files, path);
  if(f == NULL)
    f = cache_insert(path);
  pthread_mutex_unlock(&cache.lock);

  return f;
}

static bool
cache_valid(struct file *f)
{
  if(!cache.on)
    return false;

  if(f->valid - time(NULL) >= 0)
    return true;

  return false;
}

static bool
cache_file_exists(struct file *f)
{
  int result;
  struct stat st;
  char *cp = cache_path(f);

  result = stat(cp, &st);
  free(cp);

  return (result == 0) ? true : false;
}

static bool
cache_file_valid(struct file *f)
{
  char *cp;
  int result;
  struct stat st;

  if(!cache_valid(f))
    return false;

  if(!cache_file_exists(f))
    return false;

  cp = cache_path(f);
  result = stat(cp, &st);
  free(cp);

  if(result != 0)
    return false;

  if(f->st->st_mtime > st.st_mtime)
    return false;

  return true;
}

GList *
add_file_to_list(GList *list, const char *path, struct stat *st)
{
  struct file *f = g_new0(struct file, 1);
  struct stat *stbuf = g_new0(struct stat, 1);

  f->path = strdup(path);
  f->name = strdup(basename(f->path));

  if(st != NULL)
    memcpy(stbuf, st, sizeof(struct stat));

  f->st = stbuf;

  return g_list_append(list, f);
}

static int
validate_mountpoint(const char *path, struct stat *stbuf)
{
  DIR *d;

  DEBUG("validating mountpoint: %s\n", path);

  if(stat(path, stbuf) == -1) {
    fprintf(stderr, "%s: unable to stat MOUNTPOINT %s: %s\n",
        stormfs.progname, path, strerror(errno));
    return -1;
  }

  if((d = opendir(path)) == NULL) {
    fprintf(stderr, "%s: unable to open MOUNTPOINT %s: %s\n",
        stormfs.progname, path, strerror(errno));
    return -1;
  }

  closedir(d);

  return 0;
}

bool
valid_service(const char *service)
{
  bool valid = false;
  const char *valid_services[] = {
    "s3",
    "cloudfiles"
  };

  for(uint8_t i = 0; i < 2; i++)
    if(strcmp(service, valid_services[i]) == 0)
      valid = true;

  return valid;
}

bool
valid_acl(const char *acl)
{
  bool valid = false;
  const char *valid_acls[] = {
    "private",
    "public-read",
    "public-read-write",
    "authenticated-read",
    "bucket-owner-read",
    "bucket-owner-full-control"
  };

  for(uint8_t i = 0; i < 6; i++)
    if(strcmp(acl, valid_acls[i]) == 0)
      valid = true;

  return valid;
}

static int
cache_mime_types(void)
{
  FILE *f;
  char *type, *ext, *cur;
  char line[BUFSIZ];

  stormfs.mime_types = g_hash_table_new_full(g_str_hash, g_str_equal,
      g_free, g_free);

  if((f = fopen(stormfs.mime_path, "r")) == NULL) {
    fprintf(stderr, "%s: unable to open %s: %s\n",
        stormfs.progname, stormfs.mime_path, strerror(errno));
    return -errno;
  }

  while(fgets(line, BUFSIZ, f) != NULL) {
    if(*line == 0 || *line == '#')
      continue;

    type = line;
    cur  = line;

    while(*cur != ' ' && *cur != '\t' && *cur)
      cur++;

    if(*cur == 0)
      continue;

    *cur++ = 0;

    while(1) {
      while(*cur == ' ' || *cur == '\t')
        cur++;
      if(*cur == 0)
        break;

      ext = cur;
      while(*cur != ' ' && *cur != '\t' && *cur != '\n' && *cur)
        cur++;
      *cur++ = 0;

      if(*ext) {
        g_hash_table_insert(stormfs.mime_types, strdup(ext), strdup(type));
      }
    }
  }

  fclose(f);

  return 0;
}

const char *
get_mime_type(const char *filename)
{
  char *type = NULL;
  char *p = NULL, *ext = NULL;
  char *name = strdup(filename);

  p = strtok(name, ".");
  while(p != NULL) {
    if(ext != NULL)
      free(ext);

    ext = strdup(p);
    p = strtok(NULL, ".");
  }

  if(strcmp(filename, ext) == 0) {
    free(name);
    return NULL;
  }

  free(name);

  if(ext != NULL)
    type = g_hash_table_lookup(stormfs.mime_types, ext);

  free(ext);
  return type;
}

char *
get_path(const char *path, const char *name)
{
  char *fullpath;

  fullpath = g_malloc(sizeof(char) * strlen(path) + strlen(name) + 2);
  strcpy(fullpath, path);
  if(strcmp(path, "/") != 0)
    strncat(fullpath, "/", 1);
  strncat(fullpath, name, strlen(name));

  return fullpath;
}

int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  int result;
  struct file *f = NULL;

  DEBUG("getattr: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if(strcmp(path, "/") == 0) {
    stbuf->st_mode = stormfs.root_mode | S_IFDIR;
    return 0;
  }

  f = cache_get(path);
  if(cache_valid(f) && f->st != NULL) {
    memcpy(stbuf, f->st, sizeof(struct stat));
    return 0;
  }

  if((result = proxy_getattr(path, stbuf)) != 0)
    return result;

  stbuf->st_nlink = 1;
  if(S_ISREG(stbuf->st_mode))
    stbuf->st_blocks = get_blocks(stbuf->st_size);

  pthread_mutex_lock(&f->lock);
  if(f->st == NULL)
    f->st = g_new0(struct stat, 1);
  memcpy(f->st, stbuf, sizeof(struct stat));
  cache_touch(f);
  pthread_mutex_unlock(&f->lock);

  return 0;
}

int
stormfs_unlink(const char *path)
{
  int result;

  DEBUG("unlink: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if((result = proxy_unlink(path)) != 0)
    return result;

  cache_invalidate_dir(path);

  return result;
}

static int
stormfs_truncate(const char *path, off_t size)
{
  int fd;
  int result;
  struct stat st;
  struct file *f;

  DEBUG("truncate: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if((result = stormfs_getattr(path, &st)) != 0)
    return -result;

  f = cache_get(path);
  if(cache_file_valid(f)) {
    char *cp = cache_path(f);
    if((result = truncate(cp, size)) != 0)
      perror("truncate");
    free(cp);
  } else {
    fd = cache_create_file(f);
    close(fd);
  }

  pthread_mutex_lock(&f->lock);
  f->st->st_size = get_blocks(size);
  cache_touch(f);
  pthread_mutex_unlock(&f->lock);

  return 0;
}

static int
stormfs_open(const char *path, struct fuse_file_info *fi)
{
  FILE *fp;
  int fd;
  int result;
  struct file *f;

  DEBUG("open: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if(fi->flags & O_TRUNC)
    if((result = stormfs_truncate(path, 0)) != 0)
      return result;

  f = cache_get(path);
  if(cache_file_valid(f)) {
    char *cp = cache_path(f);

    fp = fopen(cp, "a+");
    free(cp);

    if(fp == NULL)
      return -errno;
    if((fd = fileno(fp)) == -1)
      return -errno;

    fi->fh = fd;

    return 0;
  }

  // file not available in cache, download it.
  if((fd = cache_create_file(f)) == -1)
    return -1; // FIXME: need to return proper errors here.
  if((fp = fdopen(fd, "a+")) == NULL)
    return -errno;

  if((result = proxy_open(path, fp)) != 0) {
    fclose(fp);
    return result;
  }

  fi->fh = fd;

  return result;
}

static int
stormfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  int result;
  struct stat st;
  struct file *f;

  DEBUG("create: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  cache_invalidate_dir(path);

  f = cache_get(path);
  fi->fh = cache_create_file(f);

  st.st_gid = getgid();
  st.st_uid = getuid();
  st.st_mode = mode;
  st.st_ctime = time(NULL);
  st.st_mtime = time(NULL);

  if((result = proxy_create(path, &st)) != 0)
    return result;

  pthread_mutex_lock(&f->lock);
  if(f->st == NULL)
    f->st = g_new0(struct stat, 1);
  memcpy(f->st, &st, sizeof(struct stat));
  cache_touch(f);
  pthread_mutex_unlock(&f->lock);

  return result;
}

static int
stormfs_chmod(const char *path, mode_t mode)
{
  int result;
  struct file *f;
  struct stat st;

  DEBUG("chmod: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if((result = stormfs_getattr(path, &st)) != 0)
    return result;

  st.st_mode = mode;
  st.st_ctime = time(NULL);
  st.st_mtime = time(NULL);

  if((result = proxy_chmod(path, &st)) != 0)
    return result;

  f = cache_get(path);
  if(cache_valid(f) && f->st != NULL) {
    pthread_mutex_lock(&f->lock);
    f->st->st_mode = mode;
    f->st->st_ctime = st.st_ctime;
    f->st->st_mtime = st.st_mtime;
    cache_touch(f);
    pthread_mutex_unlock(&f->lock);
  }

  return result;
}

static int
stormfs_chown(const char *path, uid_t uid, gid_t gid)
{
  int result = 0;
  struct file *f;
  struct stat st;

  DEBUG("chown: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if((result = stormfs_getattr(path, &st)) != 0)
    return result;

  st.st_uid = uid;
  st.st_gid = gid;
  st.st_ctime = time(NULL);
  st.st_mtime = time(NULL);

  if((result = proxy_chown(path, &st)) != 0)
    return result;

  f = cache_get(path);
  if(cache_valid(f) && f->st != NULL) {
    pthread_mutex_lock(&f->lock);
    f->st->st_uid = uid;
    f->st->st_gid = gid;
    f->st->st_ctime = st.st_ctime;
    f->st->st_mtime = st.st_mtime;
    cache_touch(f);
    pthread_mutex_unlock(&f->lock);
  }

  return result;
}

static int
stormfs_mkdir(const char *path, mode_t mode)
{
  int result;
  struct stat st;

  DEBUG("mkdir: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  cache_invalidate_dir(path);

  st.st_mode = mode;
  st.st_uid = getuid();
  st.st_gid = getgid();
  st.st_ctime = time(NULL);
  st.st_mtime = time(NULL);

  return proxy_mkdir(path, &st);
}

static int
stormfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
  int result;
  int fd;
  struct file *f;
  struct stat st;

  DEBUG("mknod: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  cache_invalidate_dir(path);

  f = cache_get(path);
  fd = cache_mknod(f, mode, rdev);

  st.st_gid = getgid();
  st.st_uid = getuid();
  st.st_mode = mode;
  st.st_rdev = rdev;
  st.st_ctime = time(NULL);
  st.st_mtime = time(NULL);

  if((result = proxy_mknod(path, &st)) != 0)
    return result;

  pthread_mutex_lock(&f->lock);
  if(f->st == NULL)
    f->st = g_new0(struct stat, 1);
  memcpy(f->st, &st, sizeof(struct stat));
  cache_touch(f);
  pthread_mutex_unlock(&f->lock);

  return result;
}

static int
stormfs_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  DEBUG("read: %s\n", path);

  return pread(fi->fh, buf, size, offset);
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi)
{
  int result;
  struct file *dir;
  GList *files = NULL, *head = NULL, *next = NULL;

  DEBUG("readdir: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  filler(buf, ".",  0, 0);
  filler(buf, "..", 0, 0);

  dir = cache_get(path);
  if(cache_valid(dir) && dir->dir != NULL) {
    pthread_mutex_lock(&dir->lock);
    head = g_list_first(dir->dir);
    while(head != NULL) {
      next = head->next;
      struct file *f = head->data;
      filler(buf, (char *) f->name, f->st, 0);
      head = next;
    }
    pthread_mutex_unlock(&dir->lock);
    return 0;
  }

  if((result = proxy_readdir(path, &files)) != 0)
    return result;

  result = proxy_getattr_multi(path, files);

  pthread_mutex_lock(&dir->lock);
  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;
    // FIXME: list_bucket is using the same structure (file) as
    // the cache which makes the code below confusing.
    struct file *file = head->data;
    char *fullpath = get_path(path, file->name);
    struct file *f = cache_get(fullpath);
    free(fullpath);

    pthread_mutex_lock(&f->lock);
    if(f->st == NULL)
      f->st = g_new0(struct stat, 1);
    memcpy(f->st, file->st, sizeof(struct stat));
    f->st->st_nlink = 1;
    cache_touch(f);
    pthread_mutex_unlock(&f->lock);

    filler(buf, (char *) f->name, f->st, 0);
    dir->dir = g_list_append(dir->dir, f);

    head = next;
  }
  pthread_mutex_unlock(&dir->lock);

  free_files(files);

  return result;
}

static int
stormfs_readlink(const char *path, char *buf, size_t size)
{
  int fd;
  FILE *fp = NULL;
  int result;
  struct stat st;
  struct file *f;

  DEBUG("readlink: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if(size <= 0)
    return 0;

  --size; // save the null byte

  f = cache_get(path);
  if(cache_file_valid(f)) {
    char *cp = cache_path(f);

    fp = fopen(cp, "a+");
    free(cp);

    if(fp == NULL)
      return -errno;
    if((fd = fileno(fp)) == -1)
      return -errno;
  } else {
    // file not available in cache, download it.
    if((fd = cache_create_file(f)) == -1)
      return -EIO;
    if((fp = fdopen(fd, "a+")) == NULL)
      return -errno;

    if((result = proxy_open(path, fp)) != 0) {
      fclose(fp);
      return result;
    }
  }

  if(fstat(fd, &st) != 0) {
    close(fd);
    return -errno;
  }

  if(st.st_size < (off_t) size)
    size = st.st_size;

  if(pread(fd, buf, size, 0) == -1) {
    close(fd);
    return -errno;
  }

  buf[size] = 0;
  if(close(fd) != 0)
    return -errno;

  return 0;
}

static int
stormfs_release(const char *path, struct fuse_file_info *fi)
{
  int result = 0;
  struct stat st;

  DEBUG("release: %s\n", path);

  /* if the file was opened read-only, we can assume it didn't
     change and skip the upload process */
  if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)) {
    if(fsync(fi->fh) != 0)
      return -errno;

    if((result = stormfs_getattr(path, &st)) != 0)
      return -result;

    result = proxy_release(path, fi->fh, &st);
  }

  if(close(fi->fh) != 0) {
    perror("close");
    return -errno;
  }

  return result;
}

static int
stormfs_rename(const char *from, const char *to)
{
  int result;
  struct stat st;

  DEBUG("rename: %s -> %s\n", from, to);

  if((result = valid_path(from)) != 0)
    return result;
  if((result = valid_path(to)) != 0)
    return result;

  if((result = stormfs_getattr(from, &st)) != 0)
    return result;

  if((result = proxy_rename(from, to, &st)) != 0)
    return result;

  // FIXME: cache_rename
  cache_invalidate_dir(from);
  cache_invalidate_dir(to);

  return result;
}

static int
stormfs_rmdir(const char *path)
{
  int result = 0;

  DEBUG("rmdir: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if((result = proxy_rmdir(path)) != 0)
    return result;

  cache_invalidate_dir(path);

  return result;
}

static int
stormfs_statfs(const char *path, struct statvfs *buf)
{
  buf->f_bavail  = 0x1000000;
  buf->f_bfree   = 0x1000000;
  buf->f_blocks  = 0x1000000;
  buf->f_bsize   = 0x1000000;
  buf->f_namemax = NAME_MAX;

  return 0;
}

static int
stormfs_symlink(const char *from, const char *to)
{
  int result;
  struct stat st;

  DEBUG("symlink: %s -> %s\n", from, to);

  if((result = valid_path(from)) != 0)
    return result;
  if((result = valid_path(to)) != 0)
    return result;

  st.st_mode = S_IFLNK;
  st.st_mtime = time(NULL);
  if((result = proxy_symlink(from, to, &st)) != 0)
    return result;

  cache_invalidate_dir(to);

  return result;
}

static int
stormfs_utimens(const char *path, const struct timespec ts[2])
{
  int result;
  struct file *f;
  struct stat st;

  DEBUG("utimens: %s\n", path);

  if((result = valid_path(path)) != 0)
    return result;

  if((result = stormfs_getattr(path, &st)) != 0)
    return result;

  st.st_mtime = ts[1].tv_sec;

  if((result = proxy_utimens(path, &st)) != 0)
    return result;

  f = cache_get(path);
  if(cache_valid(f) && f->st != NULL) {
    pthread_mutex_lock(&f->lock);
    f->st->st_mtime = st.st_mtime;
    cache_touch(f);
    pthread_mutex_unlock(&f->lock);
  }

  return result;
}

static int
stormfs_write(const char *path, const char *buf,
    size_t size, off_t offset, struct fuse_file_info *fi)
{
  struct file *f;
  DEBUG("write: %s\n", path);

  f = cache_get(path);
  if(cache_valid(f) && f->st != NULL) {
    pthread_mutex_lock(&f->lock);
    f->st->st_size += size;
    cache_touch(f);
    pthread_mutex_unlock(&f->lock);
  }

  return pwrite(fi->fh, buf, size, offset);
}

char *
stormfs_virtual_url(char *url, char *bucket)
{
  char *tmp;
  char v[strlen(url) + strlen(bucket) + 9];

  if(stormfs.ssl || (strcasestr(url, "https://")) != NULL) {
    strcpy(v, "https://");
    strncat(v, bucket, strlen(bucket));
    strncat(v, ".", 1);
    if(strcasestr(url, "https://"))
      strncat(v, url + 8, strlen(url) - 8);
    else if(strcasestr(url, "http://"))
      strncat(v, url + 7, strlen(url) - 7);
    else
      strncat(v, url, strlen(url));
  } else {
    strcpy(v, "http://");
    strncat(v, bucket, strlen(bucket));
    strncat(v, ".", 1);
    if(strcasestr(url, "http://"))
      strncat(v, url + 7, strlen(url) - 7);
    else
      strncat(v, url, strlen(url));
  }

  tmp = strdup(v);

  return tmp;
}

static void
set_defaults(void)
{
  stormfs.api = "s3";
  stormfs.cache = 1;
  stormfs.verify_ssl = 2;
  stormfs.acl = "private";
  stormfs.url = "http://s3.amazonaws.com";
  stormfs.storage_class = "STANDARD";
  stormfs.config = CONFIG;
  stormfs.mime_path = "/etc/mime.types";
  stormfs.cache_path = "/tmp/stormfs";
  stormfs.cache_timeout = DEFAULT_CACHE_TIMEOUT;
}

static void
validate_config(void)
{
  bool valid = true;

  if(!stormfs.bucket) {
    fprintf(stderr, "%s: missing BUCKET command-line option, see %s -h for usage\n",
        stormfs.progname, stormfs.progname);
    valid = false;
  }

  if(!stormfs.mountpoint) {
    fprintf(stderr, "%s: missing MOUNTPOINT command-line option, see %s -h for usage\n",
        stormfs.progname, stormfs.progname);
    valid = false;
  }

  if(!valid_service(stormfs.api)) {
    fprintf(stderr, "%s: invalid service %s, see %s -h for usage\n",
        stormfs.progname, stormfs.api, stormfs.progname);
    valid = false;
  }

  if(!valid_acl(stormfs.acl)) {
    fprintf(stderr, "%s: invalid ACL %s, see %s -h for usage\n",
        stormfs.progname, stormfs.acl, stormfs.progname);
    valid = false;
  }

  if(stormfs.access_key == NULL || stormfs.secret_key == NULL) {
    fprintf(stderr, "%s: missing access credentials, verify %s is correct\n",
        stormfs.progname, stormfs.config);
    valid = false;
  }

  if(!valid)
    exit(EXIT_FAILURE);
}

static void
validate_config_perms(struct stat *st)
{
  if((st->st_mode & S_IROTH) ||
     (st->st_mode & S_IWOTH) ||
     (st->st_mode & S_IXOTH)) {
    fprintf(stderr, "%s: WARNING: config file %s has insecure permissions!\n",
        stormfs.progname, stormfs.config);
  }
}

char *
get_config_value(char *s)
{
  if(*s == 0)
    return NULL;

  while(*s == ' ') s++;

  char *end = s + strlen(s);
  while(end > s && *end == ' ') end--;

  *(end) = '\0';

  return strdup(s);
}

static void
parse_config(const char *path)
{
  int fd;
  ssize_t n;
  char *p = NULL;
  char buf[BUFSIZ + 1];
  struct stat *st = g_malloc0(sizeof(struct stat));

  if(stat(path, st) == -1) {
    fprintf(stderr, "%s: missing configuration file %s\n",
        stormfs.progname, path);
    exit(EXIT_FAILURE);
  }

  validate_config_perms(st);

  if((fd = open(path, O_RDONLY)) == -1) {
    free(st);
    perror("open");
    fprintf(stderr, "%s: unable to open configuration file %s\n",
        stormfs.progname, path);
    exit(EXIT_FAILURE);
    return;
  }

  while((n = read(fd, buf, BUFSIZ)) > 0)
    buf[n] = '\0';

  p = strtok(buf, "\n");
  while(p != NULL) {
    while(*p == ' ')
      p++;

    if(*p == '#') {
      p = strtok(NULL, "\n");
      continue;
    }

    if(strstr(p, "service") != NULL)
      stormfs.api = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "access_key") != NULL)
      stormfs.access_key = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "secret_key") != NULL)
      stormfs.secret_key = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "url") != NULL)
      stormfs.url = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "username") != NULL)
      stormfs.username = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "acl") != NULL)
      stormfs.acl = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "expires") != NULL)
      stormfs.expires = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "use_ssl") != NULL)
      stormfs.ssl = true;
    if(strstr(p, "no_verify_ssl") != NULL)
      stormfs.verify_ssl = 0;
    if(strstr(p, "use_rrs") != NULL)
      stormfs.rrs = true;
    if(strstr(p, "encryption") != NULL)
      stormfs.encryption = true;
    if(strstr(p, "mime_path") != NULL)
      stormfs.mime_path = get_config_value(strstr(p, "=") + 1);
    if(strstr(p, "cache_path") != NULL)
      stormfs.cache_path = get_config_value(strstr(p, "=") + 1);

    p = strtok(NULL, "\n");
  }

  g_free(st);
  return;
}

static void
show_debug_header(void)
{
  DEBUG("STORMFS version:       %s\n", PACKAGE_VERSION);
  DEBUG("STORMFS service:       %s\n", stormfs.api);
  DEBUG("STORMFS config:        %s\n", stormfs.config);
  DEBUG("STORMFS url:           %s\n", stormfs.url);
  DEBUG("STORMFS username:      %s\n", stormfs.username);
  DEBUG("STORMFS bucket:        %s\n", stormfs.bucket);
  DEBUG("STORMFS virtual url:   %s\n", stormfs.virtual_url);
  DEBUG("STORMFS acl:           %s\n", stormfs.acl);
  DEBUG("STORMFS cache:         %s\n", (stormfs.cache) ? "on" : "off");
  DEBUG("STORMFS encryption:    %s\n", (stormfs.encryption) ? "on" : "off");
}

static void
set_service(void)
{
  stormfs.service = S3;

  if(strcasestr("cloudfiles", stormfs.api) != NULL) {
    stormfs.service = CLOUDFILES;
    stormfs.url = "https://auth.api.rackspace.com/v1.0";
    stormfs.ssl = true;
  }
}

static void *
stormfs_init(struct fuse_conn_info *conn)
{
  if(conn->capable & FUSE_CAP_ATOMIC_O_TRUNC)
    conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;

  if(conn->capable & FUSE_CAP_BIG_WRITES)
    conn->want |= FUSE_CAP_BIG_WRITES;

  set_service();
  cache_mime_types();
  show_debug_header();

  if(proxy_init(&stormfs) != 0) {
    fprintf(stderr, "%s: unable to initialize service\n", stormfs.progname);
    exit(EXIT_FAILURE);
  }

  if(cache_init() != 0) {
    fprintf(stderr, "%s: unable to initialize cache\n", stormfs.progname);
    exit(EXIT_FAILURE);
  }

  return NULL;
}

static void
stormfs_destroy(void *data)
{
  cache_destroy();
  proxy_destroy();
  free(stormfs.bucket);
  free(stormfs.mountpoint);
  free(stormfs.access_key);
  free(stormfs.secret_key);
  free(stormfs.virtual_url);
  g_hash_table_destroy(stormfs.mime_types);
}

static void
usage(const char *progname)
{
  printf(
"usage: %s bucket mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]         mount options\n"
"    -h   --help             print help\n"
"    -V   --version          print version\n"
"\n"
"STORMFS options:\n"
"    -o config=CONFIG        path to configuration file (default: /etc/stormfs.conf)\n"
"    -o url=URL              specify a custom service URL\n"
"    -o acl=ACL              canned acl applied to objects (default: private)\n"
"                            valid options: {private,\n"
"                                            public-read,\n"
"                                            public-read-write,\n"
"                                            authenticated-read,\n"
"                                            bucket-owner-read,\n"
"                                            bucket-owner-full-control}\n"
"    -o expires=RFC1123DATE  expires HTTP header applied to objects\n"
"                              (default: disabled)\n"
"    -o use_ssl              force the use of SSL\n"
"    -o no_verify_ssl        skip SSL certificate/host verification\n"
"    -o use_rrs              use reduced redundancy storage\n"
"    -o encryption           enable server-side encryption\n"
"    -o mime_path=PATH       path to mime.types (default: /etc/mime.types)\n"
"    -o cache_path=PATH      path for cached file storage (default: /tmp/stormfs)\n"
"    -o cache_timeout=N      sets the cache timeout in seconds (default: 300)\n"
"    -o nocache              disable the cache (cache is enabled by default)\n"
"\n", progname);
}

static struct fuse_operations stormfs_oper = {
    .create   = stormfs_create,
    .chmod    = stormfs_chmod,
    .chown    = stormfs_chown,
    .destroy  = stormfs_destroy,
    .getattr  = stormfs_getattr,
    .init     = stormfs_init,
    .mkdir    = stormfs_mkdir,
    .mknod    = stormfs_mknod,
    .open     = stormfs_open,
    .read     = stormfs_read,
    .readdir  = stormfs_readdir,
    .readlink = stormfs_readlink,
    .release  = stormfs_release,
    .rename   = stormfs_rename,
    .rmdir    = stormfs_rmdir,
    .statfs   = stormfs_statfs,
    .symlink  = stormfs_symlink,
    .truncate = stormfs_truncate,
    .unlink   = stormfs_unlink,
    .utimens  = stormfs_utimens,
    .write    = stormfs_write,
};

static int
stormfs_fuse_main(struct fuse_args *args)
{
  return fuse_main(args->argc, args->argv, &stormfs_oper, NULL);
}

static int
stormfs_opt_proc(void *data, const char *arg, int key,
    struct fuse_args *outargs)
{
  switch(key) {
    case FUSE_OPT_KEY_OPT:
      return 1;

    case FUSE_OPT_KEY_NONOPT:
      if(!stormfs.bucket) {
        stormfs.bucket = strdup((char *) arg);
        return 0;
      }

      struct stat st;
      if(validate_mountpoint(arg, &st) == -1)
        exit(EXIT_FAILURE);

      stormfs.mountpoint = strdup((char *) arg);
      stormfs.root_mode = st.st_mode;

      return 1;

    case KEY_FOREGROUND:
      stormfs.foreground = 1;
      return 1;

    case KEY_HELP:
      usage(outargs->argv[0]);
      fuse_opt_add_arg(outargs, "-ho");
      stormfs_fuse_main(outargs);
      exit(EXIT_FAILURE);

    case KEY_VERSION:
      printf("STORMFS version %s\n", PACKAGE_VERSION);
      fuse_opt_add_arg(outargs, "--version");
      stormfs_fuse_main(outargs);
      exit(0);

    default:
      fprintf(stderr, "%s: error parsing options\n", stormfs.progname);
      exit(EXIT_FAILURE);
  }
}

int
main(int argc, char *argv[])
{
  int result;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  memset(&stormfs, 0, sizeof(struct stormfs));
  stormfs.progname = argv[0];
  set_defaults();

  if(fuse_opt_parse(&args, &stormfs, stormfs_opts, stormfs_opt_proc) == -1) {
    fprintf(stderr, "%s: error parsing command-line options\n", stormfs.progname);
    exit(EXIT_FAILURE);
  }

  parse_config(stormfs.config);
  validate_config();
  if(stormfs.rrs)
    stormfs.storage_class = "REDUCED_REDUNDANCY";

  stormfs.virtual_url = stormfs_virtual_url(stormfs.url, stormfs.bucket);

  g_thread_init(NULL);
  result = stormfs_fuse_main(&args);

  fuse_opt_free_args(&args);

  return result;
}
