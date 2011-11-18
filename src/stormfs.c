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
#include <fuse.h>
#include <glib.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "stormfs.h"
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
  char *url;
  char *bucket;
  char *virtual_url;
  char *access_key;
  char *secret_key;
  char *mountpoint;
  mode_t root_mode;
} stormfs;

#define STORMFS_OPT(t, p, v) { t, offsetof(struct stormfs, p), v }

static struct fuse_opt stormfs_opts[] = {
  STORMFS_OPT("url=%s",        url,    0),
  STORMFS_OPT("use_ssl",       ssl,    1),
  STORMFS_OPT("stormfs_debug", debug,  1),

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

static struct fuse_operations stormfs_oper = {
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
    .symlink  = stormfs_symlink,
    .truncate = stormfs_truncate,
    .unlink   = stormfs_unlink,
    .utimens  = stormfs_utimens,
    .write    = stormfs_write,
};

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

static char *
name_from_xml(xmlDocPtr doc, xmlXPathContextPtr ctx)
{
  xmlChar *name;

  xmlXPathObjectPtr key = xmlXPathEvalExpression((xmlChar *) "s3:Key", ctx);
  xmlNodeSetPtr key_nodes = key->nodesetval;
  name = xmlNodeListGetString(doc, key_nodes->nodeTab[0]->xmlChildrenNode, 1);

  xmlXPathFreeObject(key);

  return (char *) name;
}

static int
validate_mountpoint(const char *path, struct stat *stbuf)
{
  DIR *d;

  DEBUG("validating mountpoint: %s\n", path);

  if(stat(path, &(*stbuf)) == -1) {
    fprintf(stderr, "unable to stat MOUNTPOINT %s: %s\n",
        path, strerror(errno));
    return -1;
  }

  if((d = opendir(path)) == NULL) {
    fprintf(stderr, "unable to open MOUNTPOINT %s: %s\n",
        path, strerror(errno));
    return -1;
  }

  closedir(d);

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

static int
stormfs_getattr(const char *path, struct stat *stbuf)
{
  int status;
  GList *headers = NULL;
  GList *head = NULL, *next = NULL;

  DEBUG("getattr: %s\n", path);

  memset(stbuf, 0, sizeof(struct stat));
  stbuf->st_nlink = 1;

  if(strcmp(path, "/") == 0) {
    stbuf->st_mode = stormfs.root_mode | S_IFDIR;

    return 0;
  }

  if((status = stormfs_curl_head(path, &headers)) != 0)
    return status;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *header = head->data;

    // TODO: clean this up.
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

  if(S_ISREG(stbuf->st_mode))
    stbuf->st_blocks = get_blocks(stbuf->st_size);

  g_list_free_full(headers, (GDestroyNotify) free_headers); 

  return 0;
}

static void *
stormfs_init(struct fuse_conn_info *conn)
{
  if(conn->capable & FUSE_CAP_ATOMIC_O_TRUNC)
    conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;

  if(conn->capable & FUSE_CAP_BIG_WRITES)
    conn->want |= FUSE_CAP_BIG_WRITES;

  return NULL;
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
stormfs_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi)
{
  int result;

  DEBUG("read: %s\n", path);

  if((result = pread(fi->fh, buf, size, offset)) == -1)
    return -errno;

  return result;
}

static int
stormfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, 
    off_t offset, struct fuse_file_info *fi)
{
  int result;
  char *xml;

  DEBUG("readdir: %s\n", path);

  result = stormfs_curl_list_bucket(path, &xml);
  if(result != 0) {
    g_free(xml);
    return -EIO;
  }

  filler(buf, ".",  0, 0);
  filler(buf, "..", 0, 0);

  if(strstr(xml, "xml") == NULL)
    return 0;

  xmlDocPtr doc;
  xmlXPathContextPtr ctx;
  xmlXPathObjectPtr contents_xp;
  xmlNodeSetPtr content_nodes;

  if((doc = xmlReadMemory(xml, strlen(xml), "", NULL, 0)) == NULL)
    return -EIO;

  ctx = xmlXPathNewContext(doc);
  xmlXPathRegisterNs(ctx, (xmlChar *) "s3",
    (xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");

  contents_xp = xmlXPathEvalExpression((xmlChar *) "//s3:Contents", ctx);
  content_nodes = contents_xp->nodesetval;

  int i;
  for(i = 0; i < content_nodes->nodeNr; i++) {
    char *name;

    ctx->node = content_nodes->nodeTab[i];
    name = name_from_xml(doc, ctx);

    filler(buf, basename(name), 0, 0);

    g_free(name);
  }

  xmlXPathFreeObject(contents_xp);
  xmlXPathFreeContext(ctx);
  xmlFreeDoc(doc);
  g_free(xml);

  return 0;
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

  --size; // save the null byte

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
stormfs_rename(const char *from, const char *to)
{
  int result;
  struct stat st;

  DEBUG("rename: %s -> %s\n", from, to);

  if((result = stormfs_getattr(from, &st)) != 0)
    return -result;

  // TODO:
  if(st.st_size >= FIVE_GB)
    return -ENOTSUP;

  // TODO:
  if(S_ISDIR(st.st_mode)) 
    result = stormfs_rename_directory(from, to);
  else
    result = stormfs_rename_file(from, to);

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
  char *xml;

  DEBUG("rename directory: %s -> %s\n", from, to);

  result = stormfs_curl_list_bucket(from, &xml);
  if(result != 0) {
    g_free(xml);
    return -EIO;
  }

  if(strstr(xml, "xml") == NULL)
    return -EIO;

  xmlDocPtr doc;
  xmlXPathContextPtr ctx;
  xmlXPathObjectPtr contents_xp;
  xmlNodeSetPtr content_nodes;

  if((doc = xmlReadMemory(xml, strlen(xml), "", NULL, 0)) == NULL)
    return -EIO;

  ctx = xmlXPathNewContext(doc);
  xmlXPathRegisterNs(ctx, (xmlChar *) "s3",
    (xmlChar *) "http://s3.amazonaws.com/doc/2006-03-01/");

  contents_xp = xmlXPathEvalExpression((xmlChar *) "//s3:Contents", ctx);
  content_nodes = contents_xp->nodesetval;

  int i;
  for(i = 0; i < content_nodes->nodeNr; i++) {
    char *tmp;
    char *name;
    char *file_from;
    char *file_to;
    struct stat st;

    ctx->node = content_nodes->nodeTab[i];
    tmp = name_from_xml(doc, ctx);
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
    if(S_ISDIR(st.st_mode))
      if((result = stormfs_rename_directory(file_from, file_to)) != 0)
        return result;
    else
      if((result = stormfs_rename_file(file_from, file_to)) != 0)
        return result;

    g_free(tmp);
    g_free(file_to);
    g_free(file_from);
  }

  xmlXPathFreeObject(contents_xp);
  xmlXPathFreeContext(ctx);
  xmlFreeDoc(doc);
  g_free(xml);

  return stormfs_rename_file(from, to);
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
stormfs_unlink(const char *path)
{
  DEBUG("unlink: %s\n", path);
  return stormfs_curl_delete(path);
}

static int
stormfs_utimens(const char *path, const struct timespec ts[2])
{
  int result;
  GList *headers = NULL;

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

    default:
      fprintf(stderr, "error parsing options\n");
      abort();
  }
}

static int
stormfs_fuse_main(struct fuse_args *args)
{
  return fuse_main(args->argc, args->argv, &stormfs_oper, NULL);
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
    strncat(v, url + 8, strlen(url) - 8);
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
  stormfs_curl_destroy();
  g_free(stormfs.virtual_url);
}

int
main(int argc, char *argv[])
{
  int status;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

  memset(&stormfs, 0, sizeof(struct stormfs));
  if(fuse_opt_parse(&args, &stormfs, stormfs_opts, stormfs_opt_proc) == -1) {
    fprintf(stderr, "error parsing command-line options\n");
    abort();
  }

  if(!stormfs.url)
    stormfs.url = "http://s3.amazonaws.com";

  stormfs.virtual_url = stormfs_virtual_url(stormfs.url, stormfs.bucket);

  DEBUG("STORMFS version:     %s\n", PACKAGE_VERSION);
  DEBUG("STORMFS url:         %s\n", stormfs.url);
  DEBUG("STORMFS bucket:      %s\n", stormfs.bucket);
  DEBUG("STORMFS virtual url: %s\n", stormfs.virtual_url);

  if(stormfs_get_credentials(&stormfs.access_key, &stormfs.secret_key) != 0) {
    fprintf(stderr, "missing api credentials\n");
    abort();
  }

  if((status = stormfs_curl_init(stormfs.bucket, stormfs.virtual_url)) != 0) {
    fprintf(stderr, "unable to initialize libcurl\n");
    abort();
  }

  stormfs_curl_set_auth(stormfs.access_key, stormfs.secret_key);

  status = stormfs_fuse_main(&args);
  fuse_opt_free_args(&args);

  return status;
}
