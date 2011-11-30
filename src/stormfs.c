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
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <libgen.h>
#include <pthread.h>
#include <fuse.h>
#include <glib.h>
#include "stormfs.h"
#include "stormfs_cache.h"
#include "stormfs_curl.h"

enum {
  KEY_HELP,
  KEY_VERSION,
  KEY_FOREGROUND,
};

struct stormfs {
  int ssl;
  int debug;
  int foreground;
  int verify_ssl;
  char *url;
  char *bucket;
  char *progname;
  char *virtual_url;
  char *access_key;
  char *secret_key;
  char *mountpoint;
  mode_t root_mode;
  GHashTable *mime_types;
  pthread_mutex_t lock;
} stormfs;

#define STORMFS_OPT(t, p, v) { t, offsetof(struct stormfs, p), v }

static struct fuse_opt stormfs_opts[] = {
  STORMFS_OPT("url=%s",        url,        0),
  STORMFS_OPT("use_ssl",       ssl,        1),
  STORMFS_OPT("no_verify_ssl", verify_ssl, 0),
  STORMFS_OPT("stormfs_debug", debug,      1),

  FUSE_OPT_KEY("-d",            KEY_FOREGROUND),
  FUSE_OPT_KEY("debug",         KEY_FOREGROUND),
  FUSE_OPT_KEY("-f",            KEY_FOREGROUND),
  FUSE_OPT_KEY("--foreground",  KEY_FOREGROUND),
  FUSE_OPT_KEY("-h",            KEY_HELP),
  FUSE_OPT_KEY("--help",        KEY_HELP),
  FUSE_OPT_KEY("-V",            KEY_VERSION),
  FUSE_OPT_KEY("--version",     KEY_VERSION),
  FUSE_OPT_END
};

#define DEBUG(format, args...) \
        do { if (stormfs.debug) fprintf(stderr, format, args); } while(0)

static uid_t
get_uid(const char *s)
{
  return (uid_t) strtoul(s, (char **) NULL, 10);
}

static gid_t
get_gid(const char *s)
{
  return (gid_t) strtoul(s, (char **) NULL, 10);
}

static mode_t
get_mode(const char *s)
{
  return (mode_t) strtoul(s, (char **) NULL, 10);
}

static time_t
get_mtime(const char *s)
{
  return (time_t) strtoul(s, (char **) NULL, 10);
}

static off_t
get_size(const char *s)
{
  return (off_t) strtoul(s, (char **) NULL, 10);
}

blkcnt_t get_blocks(off_t size)
{
  return size / 512 + 1;
}

void
free_file(struct file *f)
{
  g_free(f->name);
  g_list_free_full(f->headers, (GDestroyNotify) free_headers);
  g_free(f->stbuf);
  g_free(f);
}

GList *
add_file_to_list(GList *list, const char *name, struct stat *st)
{
  struct file *f = g_malloc0(sizeof(struct file));
  f->name = g_strdup(name);
  
  if(st == NULL)
    st = g_malloc0(sizeof(struct stat));

  f->stbuf = st;

  return g_list_append(list, f);
}

static int
validate_mountpoint(const char *path, struct stat *stbuf)
{
  DIR *d;

  DEBUG("validating mountpoint: %s\n", path);

  if(stat(path, &(*stbuf)) == -1) {
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

static int
cache_mime_types()
{
  FILE *f;
  char *type, *ext, *cur;
  char line[BUFSIZ];

  stormfs.mime_types = g_hash_table_new_full(g_str_hash, g_str_equal, 
      g_free, g_free);

  if((f = fopen("/etc/mime.types", "r")) == NULL) {
    fprintf(stderr, "%s: unable to open /etc/mime.types: %s\n", 
        stormfs.progname, strerror(errno));
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
  char *p, *ext;
  char *name = strdup(filename);

  p = strtok(name, ".");
  while(p != NULL) {
    ext = p;
    p = strtok(NULL, ".");
  }

  if(strcmp(filename, ext) == 0) {
    g_free(name);
    return NULL;
  }

  g_free(name);

  return g_hash_table_lookup(stormfs.mime_types, ext);
}

static int
headers_to_stat(GList *headers, struct stat *stbuf)
{
  GList *head = NULL,
        *next = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *header = head->data;

    /* TODO: clean this up. */
    if(strcmp(header->key, "x-amz-meta-uid") == 0)
      stbuf->st_uid = get_uid(header->value);
    else if(strcmp(header->key, "x-amz-meta-gid") == 0)
      stbuf->st_gid = get_gid(header->value);
    else if(strcmp(header->key, "x-amz-meta-mtime") == 0)
      stbuf->st_mtime = get_mtime(header->value);
    else if(strcmp(header->key, "Last-Modified") == 0 && stbuf->st_mtime == 0)
      stbuf->st_mtime = get_mtime(header->value);
    else if(strcmp(header->key, "x-amz-meta-mode") == 0)
      stbuf->st_mode |= get_mode(header->value);
    else if(strcmp(header->key, "Content-Length") == 0)
      stbuf->st_size = get_size(header->value);
    else if(strcmp(header->key, "Content-Type") == 0) {
      if(strstr(header->value, "x-directory"))
        stbuf->st_mode |= S_IFDIR;
      else
        stbuf->st_mode |= S_IFREG;
    }

    head = next;
  }

  return 0;
}

static int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  int status;
  GList *headers = NULL;

  DEBUG("getattr: %s\n", path);

  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_nlink = 1;

  if(strcmp(path, "/") == 0) {
    stbuf->st_mode = stormfs.root_mode | S_IFDIR;
    return 0;
  }

  if((status = stormfs_curl_head(path, &headers)) != 0)
    return status;
  
  if((status = headers_to_stat(headers, stbuf)) != 0)
    return status;

  if(S_ISREG(stbuf->st_mode))
    stbuf->st_blocks = get_blocks(stbuf->st_size);

  pthread_mutex_lock(&stormfs.lock);
  g_list_free_full(headers, (GDestroyNotify) free_headers); 
  pthread_mutex_unlock(&stormfs.lock);

  return 0;
}

static int
stormfs_unlink(const char *path)
{
  DEBUG("unlink: %s\n", path);
  return stormfs_curl_delete(path);
}

static int
stormfs_truncate(const char *path, off_t size)
{
  FILE *f;
  int fd;
  int result;
  struct stat st;
  GList *headers = NULL;

  DEBUG("truncate: %s\n", path);

  if((f = tmpfile()) == NULL)
    return -errno;

  if((result = stormfs_getattr(path, &st)) != 0)
    return result;

  if((result = stormfs_curl_get_file(path, f)) != 0) {
    fclose(f);
    return result;
  }

  if((fd = fileno(f)) == -1)
    return -errno;

  if(ftruncate(fd, size) != 0)
    return -errno;

  headers = g_list_append(headers, gid_header(getgid()));
  headers = g_list_append(headers, uid_header(getuid()));
  headers = g_list_append(headers, mode_header(st.st_mode));
  headers = g_list_append(headers, mtime_header(time(NULL)));
  result = stormfs_curl_upload(path, headers, fd);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  if(close(fd) != 0)
    return -errno;

  return result;
}

static int
stormfs_open(const char *path, struct fuse_file_info *fi)
{
  FILE *f;
  int fd;
  int result;

  DEBUG("open: %s\n", path);

  if((unsigned int) fi->flags & O_TRUNC)
    if((result = stormfs_truncate(path, 0)) != 0)
      return result;

  if((f = tmpfile()) == NULL)
    return -errno;

  if((result = stormfs_curl_get_file(path, f)) != 0) {
    fclose(f);
    return result;
  }

  if((fd = fileno(f)) == -1)
    return -errno;

  if(fsync(fd) != 0)
    return -errno;

  fi->fh = fd;

  return 0;
}

static int
stormfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  int result;
  GList *headers = NULL;

  DEBUG("create: %s\n", path);

  headers = g_list_append(headers, gid_header(getgid()));
  headers = g_list_append(headers, uid_header(getuid()));
  headers = g_list_append(headers, mode_header(mode));
  headers = g_list_append(headers, mtime_header(time(NULL)));
  headers = g_list_append(headers, content_header(get_mime_type(path)));

  result = stormfs_curl_put_headers(path, headers);
  g_list_free_full(headers, (GDestroyNotify) free_headers);
  if(result != 0)
    return result;

  result = stormfs_open(path, fi);

  return result;
}

static int
stormfs_chmod(const char *path, mode_t mode)
{
  int result;
  GList *headers = NULL;

  DEBUG("chmod: %s\n", path);

  if((result = stormfs_curl_head(path, &headers)) != 0)
    return result;

  headers = strip_header(headers, "x-amz-meta-mode");
  headers = g_list_append(headers, mode_header(mode));
  headers = g_list_append(headers, replace_header());
  headers = g_list_append(headers, copy_source_header(path));

  result = stormfs_curl_put_headers(path, headers);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  return result;
}

static int
stormfs_chown(const char *path, uid_t uid, gid_t gid)
{
  int result = 0;
  struct group *g;
  struct passwd *p;
  GList *headers = NULL;
  errno = 0;

  DEBUG("chown: %s\n", path);

  if((result = stormfs_curl_head(path, &headers)) != 0)
    return result;

  if((p = getpwuid(uid)) != NULL) {
    headers = strip_header(headers, "x-amz-meta-uid");
    headers = g_list_append(headers, uid_header((*p).pw_uid));
  } else {
    result = -errno;
  }

  if((g = getgrgid(gid)) != NULL) {
    headers = strip_header(headers, "x-amz-meta-gid");
    headers = g_list_append(headers, gid_header((*g).gr_gid));
  } else {
    result = -errno;
  }

  if(result != 0)
    return result;

  headers = g_list_append(headers, replace_header());
  headers = g_list_append(headers, copy_source_header(path));
  result = stormfs_curl_put_headers(path, headers);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  return result;
}

static int
stormfs_flush(const char *path, struct fuse_file_info *fi)
{
  DEBUG("flush: %s\n", path);

  if(fsync(fi->fh) != 0)
    return -errno;

  return 0;
}

static int
stormfs_mkdir(const char *path, mode_t mode)
{ 
  FILE *f;
  int fd;
  int result;
  GList *headers = NULL;

  DEBUG("mkdir: %s\n", path);

  if((f = tmpfile()) == NULL)
    return -errno;

  if((fd = fileno(f)) == -1)
    return -errno;

  if(fsync(fd) != 0)
    return -errno;

  headers = g_list_append(headers, gid_header(getgid()));
  headers = g_list_append(headers, uid_header(getuid()));
  headers = g_list_append(headers, mode_header(mode));
  headers = g_list_append(headers, mtime_header(time(NULL)));
  headers = g_list_append(headers, content_header("application/x-directory"));
  result = stormfs_curl_upload(path, headers, fd);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  if(close(fd) != 0)
    return -errno;

  return result;
}

static int
stormfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
  int result;
  GList *headers = NULL;

  DEBUG("mknod: %s\n", path);

  headers = g_list_append(headers, gid_header(getgid()));
  headers = g_list_append(headers, uid_header(getuid()));
  headers = g_list_append(headers, mode_header(mode));
  headers = g_list_append(headers, mtime_header(time(NULL)));

  result = stormfs_curl_put_headers(path, headers);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  return result;
}

int
stormfs_getattr_multi(const char *path, GList *files)
{
  DEBUG("getattr_multi: %s\n", path);

  int result;
  GList *head = NULL, *next = NULL;
  result = stormfs_curl_head_multi(path, files);

  head = g_list_first(files);
  while(head != NULL) {
    next = head->next;

    struct file *f = head->data;
    GList *headers = f->headers;
    struct stat *stbuf = f->stbuf;
    if((result = headers_to_stat(headers, stbuf)) != 0)
      return result;

    if(S_ISREG(stbuf->st_mode))
      stbuf->st_blocks = get_blocks(stbuf->st_size);

    head = next;
  }

  return result;
}

static void *
stormfs_init(struct fuse_conn_info *conn)
{
  if(conn->capable & FUSE_CAP_ATOMIC_O_TRUNC)
    conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;

  if(conn->capable & FUSE_CAP_BIG_WRITES)
    conn->want |= FUSE_CAP_BIG_WRITES;

  cache_mime_types();

  return NULL;
}

static int
stormfs_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  DEBUG("read: %s\n", path);

  return pread(fi->fh, buf, size, offset);
}

int
stormfs_list_bucket(const char *path, GList **files)
{
  int result;
  char *xml = NULL, *start_p = NULL;

  result = stormfs_curl_list_bucket(path, &xml);
  if(result != 0) {
    g_free(xml);
    return -EIO;
  }

  if(strstr(xml, "xml") == NULL)
    return 0;

  if((start_p = strstr(xml, "<Key>")) != NULL)
    start_p += strlen("<Key>");

  while(start_p != NULL) {
    char *name;
    char *end_p = strstr(start_p, "</Key>");
     
    name = g_strndup(start_p, end_p - start_p);
    *files = add_file_to_list(*files, basename(name), NULL);
    g_free(name);

    if((start_p = strstr(end_p, "<Key>")) != NULL)
      start_p += strlen("<Key>");
  }

  g_free(xml);

  return 0;
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
    off_t offset, struct fuse_file_info *fi)
{
  int result;
  GList *files = NULL, *next = NULL;

  DEBUG("readdir: %s\n", path);

  if((result = stormfs_list_bucket(path, &files)) != 0)
    return result;

  filler(buf, ".",  0, 0);
  filler(buf, "..", 0, 0);

  files = g_list_first(files);
  while(files != NULL) {
    next = files->next;
    struct file *file = files->data;
    filler(buf, (char *) file->name, file->stbuf, 0);
    files = next;
  }

  g_list_free_full(files, (GDestroyNotify) free_file);

  return result;
}

static int
stormfs_readlink(const char *path, char *buf, size_t size)
{
  int fd;
  FILE *f;
  int result;
  struct stat st;

  DEBUG("readlink: %s\n", path);

  if(size <= 0)
    return 0;

  --size; /* save the null byte */

  if((f = tmpfile()) == NULL)
    return -errno;

  if((result = stormfs_curl_get_file(path, f)) != 0) {
    fclose(f);
    return result;
  }

  if((fd = fileno(f)) == -1)
    return -errno;

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
  int flags;
  int result = 0;

  DEBUG("release: %s\n", path);
  
  if((fi->flags & O_RDWR) || (fi->flags & O_WRONLY)) {
    GList *headers = NULL;

    if((result = stormfs_curl_head(path, &headers)) != 0)
      return result;

    headers = strip_header(headers, "x-amz-meta-mtime");
    headers = g_list_append(headers, mtime_header(time(NULL)));

    result = stormfs_curl_upload(path, headers, fi->fh);
    g_list_free_full(headers, (GDestroyNotify) free_headers);
  }

  if(close(fi->fh) != 0)
    return -errno;

  return result;
}

static int
stormfs_rename_file(const char *from, const char *to)
{
  int result;
  GList *headers = NULL;

  DEBUG("rename file: %s -> %s\n", from, to);

  if((result = stormfs_curl_head(from, &headers)) != 0)
    return result;

  headers = g_list_append(headers, copy_meta_header());
  headers = g_list_append(headers, copy_source_header(from));

  result = stormfs_curl_put_headers(to, headers);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  return stormfs_unlink(from);
}

static int
stormfs_rename_directory(const char *from, const char *to)
{
  int result;
  char *xml = NULL, *start_p = NULL;

  DEBUG("rename directory: %s -> %s\n", from, to);

  result = stormfs_curl_list_bucket(from, &xml);
  if(result != 0) {
    g_free(xml);
    return -EIO;
  }

  if(strstr(xml, "xml") == NULL)
    return -EIO;

  if((start_p = strstr(xml, "<Key>")) != NULL)
    start_p += strlen("<Key>");

  while(start_p != NULL) {
    char *name, *tmp, *file_from, *file_to;
    char *end_p = strstr(start_p, "</Key>");
    struct stat st;
     
    tmp = g_strndup(start_p, end_p - start_p);
    name = basename(tmp);

    file_from = g_malloc(sizeof(char) * strlen(from) + strlen(name) + 2);
    file_from = strcpy(file_from, from);
    file_from = strncat(file_from, "/", 1);
    file_from = strncat(file_from, name, strlen(name));

    file_to = g_malloc(sizeof(char) * strlen(to) + strlen(name) + 2);
    file_to = strcpy(file_to, to);
    file_to = strncat(file_to, "/", 1);
    file_to = strncat(file_to, name, strlen(name));

    stormfs_getattr(file_from, &st);
    if(S_ISDIR(st.st_mode)) {
      if((result = stormfs_rename_directory(file_from, file_to)) != 0)
        return result;
    } else {
      if((result = stormfs_rename_file(file_from, file_to)) != 0)
        return result;
    }

    g_free(tmp);
    g_free(file_to);
    g_free(file_from);

    if((start_p = strstr(end_p, "<Key>")) != NULL)
      start_p += strlen("<Key>");
  }

  g_free(xml);

  return stormfs_rename_file(from, to);
}

static int
stormfs_rename(const char *from, const char *to)
{
  int result;
  struct stat st;

  DEBUG("rename: %s -> %s\n", from, to);

  if((result = stormfs_getattr(from, &st)) != 0)
    return -result;

  /* TODO: */
  if(st.st_size >= FIVE_GB)
    return -ENOTSUP;

  if(S_ISDIR(st.st_mode)) 
    result = stormfs_rename_directory(from, to);
  else
    result = stormfs_rename_file(from, to);

  return result;
}

static int
stormfs_rmdir(const char *path)
{
  int result = 0;
  char *data;

  DEBUG("rmdir: %s\n", path);

  if((result = stormfs_curl_get(path, &data)) != 0) {
    g_free(data);
    return result;
  }

  if(strstr(data, "ETag") != NULL) {
    g_free(data);
    return -ENOTEMPTY;
  }

  g_free(data);

  return stormfs_curl_delete(path);
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
  int fd;
  int result;
  mode_t mode = S_IFLNK;
  GList *headers = NULL;

  DEBUG("symlink: %s -> %s\n", from, to);

  if((fd = fileno(tmpfile())) == -1)
    return -errno;

  if(pwrite(fd, from, strlen(from), 0) == -1) {
    close(fd);
    return -errno;
  }

  headers = g_list_append(headers, mode_header(mode));
  headers = g_list_append(headers, mtime_header(time(NULL)));
  result = stormfs_curl_upload(to, headers, fd);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  if(close(fd) != 0)
    return -errno;

  return result;
}

static int
stormfs_utimens(const char *path, const struct timespec ts[2])
{
  int result;
  GList *headers = NULL;

  DEBUG("utimens: %s\n", path);

  if((result = stormfs_curl_head(path, &headers)) != 0)
    return result;

  headers = strip_header(headers, "x-amz-meta-mtime");
  headers = g_list_append(headers, mtime_header(ts[1].tv_sec));
  headers = g_list_append(headers, replace_header());
  headers = g_list_append(headers, copy_source_header(path));

  result = stormfs_curl_put_headers(path, headers);
  g_list_free_full(headers, (GDestroyNotify) free_headers);

  return result;
}

static int
stormfs_write(const char *path, const char *buf, 
    size_t size, off_t offset, struct fuse_file_info *fi)
{
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
    else
      strncat(v, url + 7, strlen(url) - 7);
  } else {
    strcpy(v, "http://");
    strncat(v, bucket, strlen(bucket));
    strncat(v, ".", 1);
    strncat(v, url + 7, strlen(url) - 7);
  }

  tmp = strdup(v);

  return tmp;
}

static int
stormfs_get_credentials(char **access_key, char **secret_key)
{
  *access_key = getenv("AWS_ACCESS_KEY_ID");
  *secret_key = getenv("AWS_SECRET_ACCESS_KEY");

  if(*access_key == NULL || *secret_key == NULL)
    return -1;

  return 0;
}

static void
stormfs_destroy(void *data)
{
  pthread_mutex_destroy(&stormfs.lock);
  stormfs_curl_destroy();
  g_free(stormfs.virtual_url);
  g_hash_table_destroy(stormfs.mime_types);
}

static void
usage(const char *progname)
{
  printf(
"usage: %s bucket mountpoint [options]\n"
"\n"
"general options:\n"
"    -o opt,[opt...]        mount options\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"\n"
"STORMFS options:\n"
"    -o url=URL             specify a custom service URL\n"
"    -o use_ssl             force the use of SSL\n"
"    -o no_verify_ssl       skip SSL certificate/host verification\n"
"    -o cache=BOOL          enable caching {yes,no} (default: yes)\n"
"    -o cache_timeout=N     sets timeout for caches in seconds (default: 300)\n"
"    -o cache_X_timeout=N   sets timeout for {stat,dir,link} cache\n"
"\n", progname);
}

static struct fuse_cache_operations stormfs_oper = {
  .oper = {
    .create   = stormfs_create,
    .chmod    = stormfs_chmod,
    .chown    = stormfs_chown,
    .destroy  = stormfs_destroy,
    .getattr  = stormfs_getattr,
    .init     = stormfs_init,
    .flush    = stormfs_flush,
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
  },
  .list_bucket = stormfs_list_bucket,
};

static int
stormfs_fuse_main(struct fuse_args *args)
{
  return fuse_main(args->argc, args->argv, cache_init(&stormfs_oper), NULL);
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
        stormfs.bucket = (char *) arg;
        return 0;
      }

      struct stat stbuf;
      if(validate_mountpoint(arg, &stbuf) == -1)
        abort();

      stormfs.mountpoint = (char *) arg;
      stormfs.root_mode = stbuf.st_mode;

      return 1;

    case KEY_FOREGROUND:
      stormfs.foreground = 1;
      return 1;

    case KEY_HELP:
      usage(outargs->argv[0]);
      fuse_opt_add_arg(outargs, "-ho");
      stormfs_fuse_main(outargs);
      exit(1);

    case KEY_VERSION:
      printf("STORMFS version %s\n", PACKAGE_VERSION);
      fuse_opt_add_arg(outargs, "--version");
      stormfs_fuse_main(outargs);
      exit(0);

    default:
      fprintf(stderr, "%s: error parsing options\n", stormfs.progname);
      abort();
  }
}

int
main(int argc, char *argv[])
{
  int status;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  memset(&stormfs, 0, sizeof(struct stormfs));
  stormfs.progname = argv[0];
  stormfs.verify_ssl = 2;
  stormfs.url = "http://s3.amazonaws.com";
  pthread_mutex_init(&stormfs.lock, NULL);

  if(fuse_opt_parse(&args, &stormfs, stormfs_opts, stormfs_opt_proc) == -1) {
    fprintf(stderr, "%s: error parsing command-line options\n", stormfs.progname);
    abort();
  }

  if(!stormfs.bucket) {
    fprintf(stderr, "%s: missing BUCKET command-line option, see %s -h for usage\n",
        stormfs.progname, stormfs.progname);
    abort();
  }

  if(!stormfs.mountpoint) {
    fprintf(stderr, "%s: missing MOUNTPOINT command-line option, see %s -h for usage\n",
        stormfs.progname, stormfs.progname);
    abort();
  }


  stormfs.virtual_url = stormfs_virtual_url(stormfs.url, stormfs.bucket);

  if(cache_parse_options(&args) == -1)
    abort();

  DEBUG("STORMFS version:     %s\n", PACKAGE_VERSION);
  DEBUG("STORMFS url:         %s\n", stormfs.url);
  DEBUG("STORMFS bucket:      %s\n", stormfs.bucket);
  DEBUG("STORMFS virtual url: %s\n", stormfs.virtual_url);

  if(stormfs_get_credentials(&stormfs.access_key, &stormfs.secret_key) != 0) {
    fprintf(stderr, "%s: missing api credentials\n", stormfs.progname);
    abort();
  }

  if((status = stormfs_curl_init(stormfs.bucket, stormfs.virtual_url)) != 0) {
    fprintf(stderr, "%s: unable to initialize libcurl\n", stormfs.progname);
    abort();
  }

  stormfs_curl_set_auth(stormfs.access_key, stormfs.secret_key);
  stormfs_curl_verify_ssl(stormfs.verify_ssl);

  status = stormfs_fuse_main(&args);
  fuse_opt_free_args(&args);

  return status;
}
