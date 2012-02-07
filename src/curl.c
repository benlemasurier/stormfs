/*
 * stormfs - A FUSE abstraction layer for cloud storage
 * Copyright (C) 2011 Ben LeMasurier <ben.lemasurier@gmail.com>
 *
 * This program can be distributed under the terms of the GNU GPL.
 * See the file COPYING.
 */

#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <pthread.h>
#include <glib.h>
#include "stormfs.h"
#include "curl.h"
#include "s3-curl.h" // fixme: temp.

#define CURL_RETRIES 3
#define POOL_SIZE 100

static pthread_mutex_t lock        = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t shared_lock = PTHREAD_MUTEX_INITIALIZER;

struct stormfs_curl {
  int verify_ssl;
  const char *url;
  const char *bucket;
  const char *access_key;
  const char *secret_key;
  GList *pool;
  GList *marker;
  bool pool_full;
  CURLM *multi;
  CURLSH *share;
} curl;

typedef struct {
  CURL *c;
  bool in_use;
} CURL_HANDLE;

uid_t
get_uid(const char *s)
{
  return (uid_t) strtoul(s, (char **) NULL, 10);
}

gid_t
get_gid(const char *s)
{
  return (gid_t) strtoul(s, (char **) NULL, 10);
}

mode_t
get_mode(const char *s)
{
  return (mode_t) strtoul(s, (char **) NULL, 10);
}

time_t
get_ctime(const char *s)
{
  return (time_t) strtoul(s, (char **) NULL, 10);
}

time_t
get_mtime(const char *s)
{
  return (time_t) strtoul(s, (char **) NULL, 10);
}

dev_t
get_rdev(const char *s)
{
  return (dev_t) strtoul(s, (char **) NULL, 10);
}

off_t
get_size(const char *s)
{
  return (off_t) strtoul(s, (char **) NULL, 10);
}

char *
gid_to_s(gid_t gid)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) gid);

  return strdup(s);
}

char *
mode_to_s(mode_t mode)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) mode);

  return strdup(s);
}

char *
rdev_to_s(dev_t rdev)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) rdev);

  return strdup(s);
}

char *
time_to_s(time_t t)
{
  char s[100];
  snprintf(s, 100, "%ld", (long) t);

  return strdup(s);
}

char *
uid_to_s(uid_t uid)
{
  char s[100];
  snprintf(s, 100, "%lu", (unsigned long) uid);

  return strdup(s);
}

GList *
add_header(GList *headers, HTTP_HEADER *h)
{
  headers = strip_header(headers, h->key);
  headers = g_list_append(headers, h);

  return headers;
}

GList *
stat_to_headers(GList *headers, struct stat *st)
{
  headers = add_header(headers, gid_header(st->st_gid));
  headers = add_header(headers, uid_header(st->st_uid));
  headers = add_header(headers, mode_header(st->st_mode));
  headers = add_header(headers, ctime_header(st->st_ctime));
  headers = add_header(headers, mtime_header(st->st_mtime));
  headers = add_header(headers, rdev_header(st->st_rdev));

  return headers;
}

char
char_to_hex(char c)
{
  static char hex[] = "0123456789abcdef";

  return hex[c & 15];
}

int
cmpstringp(const void *p1, const void *p2)
{
  return strcmp(*(char **) p1, *(char **) p2);
}

void
free_header(HTTP_HEADER *h)
{
  free(h->key);
  free(h->value);
  free(h);
}

void
free_headers(GList *headers)
{
  g_list_foreach(headers, (GFunc) free_header, NULL);
  g_list_free(headers);
}

char *
url_encode(char *s)
{
  char *p = s;
  char *buf = g_malloc((strlen(s) * 3) + 1);
  char *pbuf = buf;

  // NOTE: '/' will not be url encoded
  while(*p) {
    if(isalnum(*p) || *p == '/' || *p == '-' || *p == '_' || *p == '.' || *p == '~')
      *pbuf++ = *p;
    else if(*p == ' ')
      *pbuf++ = '+';
    else
      *pbuf++ = '%', *pbuf++ = char_to_hex(*p >> 4), *pbuf++ = char_to_hex(*p & 15);

    p++;
  }

  *pbuf = '\0';
  return buf;
}

GList *
strip_header(GList *headers, const char *key)
{
  GList *head = NULL, *next = NULL;

  head = g_list_first(headers);
  while(head != NULL) {
    next = head->next;
    HTTP_HEADER *header = head->data;

    if(strstr(header->key, key) != NULL)
      headers = g_list_remove(headers, head->data);

    head = next;
  }

  return headers;
}

char *
header_to_s(HTTP_HEADER *h)
{
  char *s;
  s = g_malloc0(sizeof(char) * strlen(h->key) + strlen(h->value) + 2);
  s = strcpy(s, h->key);
  s = strcat(s, ":");
  s = strncat(s, h->value, strlen(h->value));

  return s;
}

char *
rfc2822_timestamp(void)
{
  char s[40];
  char *date;

  time_t t = time(NULL);
  strftime(s, sizeof(s), "%a, %d %b %Y %T GMT", gmtime(&t));

  date = strdup(s);

  return date;
}

CURLM *
get_multi_handle(void)
{
  return curl.multi;
}

static int
http_response_errno(CURLcode response_code, CURL *handle)
{
  long http_response;

  switch(response_code) {
    case CURLE_OK:
      if(curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_response) != 0)
        return -EIO;
      if(http_response == 401)
        return -EACCES;
      if(http_response == 403)
        return -EACCES;
      if(http_response == 404)
        return -ENOENT;
      if(http_response >= 400 && http_response < 500)
        return -EIO;
      if(http_response >= 500)
        return -EAGAIN;

      return 0;

    case CURLE_COULDNT_RESOLVE_HOST:
      return -EAGAIN;
    case CURLE_COULDNT_CONNECT:
      return -EAGAIN;
    case CURLE_WRITE_ERROR:
      return -EAGAIN;
    case CURLE_UPLOAD_FAILED:
      return -EAGAIN;
    case CURLE_READ_ERROR:
      return -EAGAIN;
    case CURLE_OPERATION_TIMEDOUT:
      return -EAGAIN;
    case CURLE_SEND_ERROR:
      return -EAGAIN;
    case CURLE_RECV_ERROR:
      return -EAGAIN;
    case CURLE_AGAIN:
      return -EAGAIN;

    default:
      return -EIO;
  }

  return 0;
}

static void
share_lock(CURL *c, curl_lock_data data, curl_lock_access laccess, void *p)
{
  pthread_mutex_lock(&shared_lock);
}

static void
share_unlock(CURL *c, curl_lock_data data, void *p)
{
  pthread_mutex_unlock(&shared_lock);
}

int
stormfs_curl_easy_perform(CURL *c)
{
  int result;
  CURLcode code;
  uint8_t attempts = 0;

  code = curl_easy_perform(c);
  while(attempts < CURL_RETRIES) {
    if((result = http_response_errno(code, c)) != -EAGAIN)
      break;

    attempts++;
    curl_easy_perform(c);
  }

  return result;
}

static int
set_curl_defaults(CURL *c)
{
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(c, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt(c, CURLOPT_USERAGENT, "stormfs");
  curl_easy_setopt(c, CURLOPT_DNS_CACHE_TIMEOUT, -1);
  curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, curl.verify_ssl);
  curl_easy_setopt(c, CURLOPT_SHARE, curl.share);

  // curl_easy_setopt(c, CURLOPT_TCP_NODELAY, 1);
  // curl_easy_setopt(c, CURLOPT_VERBOSE, 1L);
  // curl_easy_setopt(c, CURLOPT_FORBID_REUSE, 1);

  return 0;
}

size_t
read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct post_data *pd = userp;

  if(size*nmemb < 1)
    return 0;

  if(pd->remaining) {
    *(char *)ptr = pd->readptr[0];
    pd->readptr++;
    pd->remaining--;
    return 1;
  }

  return 0;
}

size_t
write_memory_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  HTTP_RESPONSE *mem = data;

  mem->memory = g_realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    fprintf(stderr, "stormfs: memory allocation failed\n");
    exit(EXIT_FAILURE);
  }

  memcpy(&(mem->memory[mem->size]), ptr, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

static CURL *
get_curl_handle(const char *url)
{
  CURL *c;
  c = curl_easy_init();
  set_curl_defaults(c);
  curl_easy_setopt(c, CURLOPT_URL, url);

  return c;
}

static int
destroy_curl_handle(CURL *c)
{
  curl_easy_cleanup(c);

  return 0;
}

static CURL_HANDLE *
create_pooled_handle(const char *url)
{
  CURL_HANDLE *ch = g_new0(CURL_HANDLE, 1);
  ch->c = get_curl_handle(url);
  ch->in_use = false;

  return ch;
}

static int
destroy_pooled_handle(CURL_HANDLE *ch)
{
  destroy_curl_handle(ch->c);
  free(ch);

  return 0;
}

static int
destroy_pool(void)
{
  g_list_foreach(curl.pool, (GFunc) destroy_pooled_handle, NULL);
  g_list_free(curl.pool);

  return 0;
}

static int
pool_init(void)
{
  curl.pool_full = false;
  for(uint8_t i = 0; i < POOL_SIZE; i++)
    curl.pool = g_list_append(curl.pool, create_pooled_handle(curl.url));

  return 0;
}

CURL *
get_pooled_handle(const char *url)
{
  GList *head = NULL, *next = NULL;

  pthread_mutex_lock(&lock);

  /* attempt to immediately grab the next available handle */
  if(curl.marker != NULL)
    head = curl.marker;
  else
    head = g_list_first(curl.pool);

  while(head != NULL && !curl.pool_full) {
    if(head->next != NULL)
      next = head->next;
    else
      next = g_list_first(curl.pool);

    CURL_HANDLE *ch = head->data;
    if(!ch->in_use) {
      ch->in_use = true;
      curl_easy_setopt(ch->c, CURLOPT_URL, url);
      curl.marker = next;
      pthread_mutex_unlock(&lock);
      return ch->c;
    }

    head = next;
    if(head == curl.marker) {
      curl.pool_full = true;
      break;
    }
  }

  pthread_mutex_unlock(&lock);

  // no handles available in the pool, create a new one.
  return get_curl_handle(url);
}

void
release_pooled_handle(CURL *c)
{
  bool is_pooled_handle = false;
  GList *head = NULL, *next = NULL;

  pthread_mutex_lock(&lock);
  head = g_list_first(curl.pool);
  while(head != NULL) {
    next = head->next;
    CURL_HANDLE *ch = head->data;
    if(ch->c == c) {
      curl_easy_reset(ch->c);
      ch->in_use = false;
      curl.pool_full = false;
      is_pooled_handle = true;
      break;
    }
    head = next;
  }
  pthread_mutex_unlock(&lock);

  if(!is_pooled_handle)
    destroy_curl_handle(c);
}

HTTP_REQUEST *
new_request(const char *path)
{
  HTTP_REQUEST *request = g_new0(HTTP_REQUEST, 1);

  request->done = false;
  request->path = strdup(path);
  request->url = get_url(path);
  request->c = get_pooled_handle(request->url);
  request->response.memory = g_malloc0(1);
  request->response.size = 0;

  return request;
}

int
free_request(HTTP_REQUEST *request)
{
  if(request == NULL)
    return 0;

  free(request->response.memory);
  release_pooled_handle(request->c);
  free(request->url);
  free(request->path);
  curl_slist_free_all(request->headers);
  free(request);

  return 0;
}

int
stormfs_curl_delete(const char *path)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("DELETE", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_CUSTOMREQUEST, "DELETE");
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);

  result = stormfs_curl_easy_perform(request->c);
  free_request(request);

  return result;
}

int
stormfs_curl_get(const char *path, char **data)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("GET", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  curl_easy_setopt(request->c, CURLOPT_WRITEDATA, (void *) &request->response);
  curl_easy_setopt(request->c, CURLOPT_WRITEFUNCTION, write_memory_cb);
  result = stormfs_curl_easy_perform(request->c);

  *data = strdup(request->response.memory);
  free_request(request);

  return result;
}

int
stormfs_curl_get_file(const char *path, FILE *f)
{
  int result;
  HTTP_REQUEST *request = new_request(path);

  sign_request("GET", &request->headers, path);
  curl_easy_setopt(request->c, CURLOPT_WRITEDATA, f);
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  result = stormfs_curl_easy_perform(request->c);

  rewind(f);
  free_request(request);

  return result;
}

int
stormfs_curl_head(HTTP_REQUEST *request)
{
  curl_easy_setopt(request->c, CURLOPT_NOBODY, 1L);    // HEAD
  curl_easy_setopt(request->c, CURLOPT_FILETIME, 1L);  // Last-Modified
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  curl_easy_setopt(request->c, CURLOPT_HEADERDATA, (void *) &request->response);
  curl_easy_setopt(request->c, CURLOPT_HEADERFUNCTION, write_memory_cb);

  return stormfs_curl_easy_perform(request->c);
}

int
stormfs_curl_upload(const char *path, GList *headers, int fd)
{
  FILE *f;
  int result;
  struct stat st;
  HTTP_REQUEST *request;

  if(fstat(fd, &st) != 0) {
    perror("fstat");
    return -errno;
  }

  if(st.st_size >= MAX_FILE_SIZE)
    return -EFBIG;

  if(st.st_size >= MULTIPART_MIN)
    return upload_multipart(path, headers, fd);

  if(lseek(fd, 0, SEEK_SET) == -1) {
    perror("lseek");
    return -errno;
  }

  if((f = fdopen(fd, "rb")) == NULL) {
    perror("fdopen");
    return -errno;
  }

  request = new_request(path);
  request->headers = headers_to_curl_slist(headers);

  sign_request("PUT", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_INFILE, f);
  curl_easy_setopt(request->c, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(request->c, CURLOPT_INFILESIZE_LARGE, (curl_off_t) st.st_size);
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  result = stormfs_curl_easy_perform(request->c);

  free_request(request);

  return result;
}

int
stormfs_curl_put(HTTP_REQUEST *request)
{
  sign_request("PUT", &request->headers, request->path);
  curl_easy_setopt(request->c, CURLOPT_UPLOAD, 1L);    // HTTP PUT
  curl_easy_setopt(request->c, CURLOPT_INFILESIZE, 0); // Content-Length: 0
  curl_easy_setopt(request->c, CURLOPT_HTTPHEADER, request->headers);
  curl_easy_setopt(request->c, CURLOPT_WRITEDATA, (void *) &request->response);
  curl_easy_setopt(request->c, CURLOPT_WRITEFUNCTION, write_memory_cb);

  return stormfs_curl_easy_perform(request->c);
}

static int
stormfs_curl_set_auth(const char *access_key, const char *secret_key)
{
  curl.access_key = access_key;
  curl.secret_key = secret_key;

  return 0;
}

static int
stormfs_curl_verify_ssl(int verify)
{
  if(verify == 0)
    curl.verify_ssl = 0;
  else
    curl.verify_ssl = 1;

  return 0;
}

void
stormfs_curl_destroy()
{
  destroy_pool();
  curl_share_cleanup(curl.share);
  curl_multi_cleanup(curl.multi);
  curl_global_cleanup();
}

static int
multi_init()
{
  if((curl.multi = curl_multi_init()) == NULL)
    return -1;

  return 0;
}

static int
share_init()
{
  CURLSHcode scode = CURLSHE_OK;
  if((curl.share = curl_share_init()) == NULL)
    return -1;
  if((scode = curl_share_setopt(curl.share,
          CURLSHOPT_LOCKFUNC, share_lock)) != CURLSHE_OK)
    return -1;
  if((scode = curl_share_setopt(curl.share,
          CURLSHOPT_UNLOCKFUNC, share_unlock)) != CURLSHE_OK)
    return -1;
  if((scode = curl_share_setopt(curl.share,
          CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS)) != CURLSHE_OK)
    return -1;

  return 0;
}

int
stormfs_curl_init(struct stormfs *stormfs)
{
  CURLcode result;
  curl.url = stormfs->virtual_url;
  curl.bucket = stormfs->bucket;
  curl.verify_ssl = 1;

  stormfs_curl_set_auth(stormfs->access_key, stormfs->secret_key);
  stormfs_curl_verify_ssl(stormfs->verify_ssl);

  if((result = curl_global_init(CURL_GLOBAL_ALL)) != CURLE_OK)
    return -1;
  if(share_init() != 0)
    return -1;
  if(multi_init() != 0)
    return -1;
  if(pool_init() != 0)
    return -1;

  return 0;
}
